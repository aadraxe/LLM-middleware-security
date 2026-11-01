using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace LlmGuard;

/// <summary>
/// <see cref="DelegatingHandler"/> for HttpClients that call LLM providers. Before an
/// OpenAI-compatible request leaves the app, the content of every message in
/// <c>messages</c> (and a top-level <c>prompt</c>, for completion-style APIs) is screened.
/// Messages are checked concurrently. If any is blocked the request is not sent and
/// <see cref="LlmGuardBlockedException"/> is thrown; under <see cref="FailMode.FailClosed"/>
/// an unscreenable message throws <see cref="LlmGuardUnavailableException"/>.
/// Requests that aren't JSON or carry no messages pass through unchanged.
/// </summary>
public sealed class LlmGuardHandler : DelegatingHandler
{
    private readonly ILlmGuardClient _guard;
    private readonly ILogger<LlmGuardHandler> _logger;

    /// <summary>Created by <c>AddLlmGuardHandler()</c>.</summary>
    public LlmGuardHandler(ILlmGuardClient guard, ILogger<LlmGuardHandler> logger)
    {
        _guard = guard;
        _logger = logger;
    }

    /// <inheritdoc />
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        if (request.Content is null || !LooksLikeJson(request.Content))
        {
            return await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
        }

        // Buffer so the body can be read here and still be sent afterwards
        await request.Content.LoadIntoBufferAsync().ConfigureAwait(false);
        var body = await request.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
        var messages = ChatPayload.ExtractMessages(body);
        if (messages.Count == 0)
        {
            Log.Skipped(_logger, request.RequestUri?.AbsolutePath ?? "", "no chat messages in request body");
            return await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
        }

        var decisions = await Task.WhenAll(messages.Select(m =>
            _guard.CheckAsync(m.Text, m.Source, cancellationToken))).ConfigureAwait(false);

        for (var i = 0; i < decisions.Length; i++)
        {
            if (decisions[i].Outcome == GuardOutcome.Blocked)
            {
                throw new LlmGuardBlockedException(decisions[i], messages[i].Index, messages[i].Role);
            }
        }
        for (var i = 0; i < decisions.Length; i++)
        {
            if (decisions[i].Outcome == GuardOutcome.FailedClosed)
            {
                throw new LlmGuardUnavailableException(decisions[i], messages[i].Index, messages[i].Role);
            }
        }
        return await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
    }

    private static bool LooksLikeJson(HttpContent content)
    {
        var mediaType = content.Headers.ContentType?.MediaType;
        return mediaType is null
            || mediaType.Equals("application/json", StringComparison.OrdinalIgnoreCase)
            || mediaType.EndsWith("+json", StringComparison.OrdinalIgnoreCase);
    }
}

/// <summary>Extracts screenable text from an OpenAI-compatible request body.</summary>
internal static class ChatPayload
{
    internal sealed record Message(int Index, string? Role, string Source, string Text);

    /// <summary>
    /// One entry per message with text content. <c>content</c> may be a string or an array of
    /// parts, whose <c>text</c> parts are joined. Tool and function results are screened as
    /// <c>rag</c> (retrieved / untrusted content); everything else as <c>user</c>. A top-level
    /// <c>prompt</c> string (completions API) is included with index -1.
    /// </summary>
    public static IReadOnlyList<Message> ExtractMessages(byte[] body)
    {
        var result = new List<Message>();
        if (body.Length == 0)
        {
            return result;
        }
        try
        {
            using var document = JsonDocument.Parse(body);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                return result;
            }
            if (root.TryGetProperty("prompt", out var prompt) && prompt.ValueKind == JsonValueKind.String
                && prompt.GetString() is { Length: > 0 } promptText)
            {
                result.Add(new Message(-1, null, "user", promptText));
            }
            if (!root.TryGetProperty("messages", out var messages) || messages.ValueKind != JsonValueKind.Array)
            {
                return result;
            }
            var index = 0;
            foreach (var message in messages.EnumerateArray())
            {
                if (message.ValueKind == JsonValueKind.Object)
                {
                    var role = message.TryGetProperty("role", out var r) && r.ValueKind == JsonValueKind.String
                        ? r.GetString() : null;
                    var text = message.TryGetProperty("content", out var content) ? ContentText(content) : null;
                    if (!string.IsNullOrEmpty(text))
                    {
                        var source = role is "tool" or "function" ? "rag" : "user";
                        result.Add(new Message(index, role, source, text));
                    }
                }
                index++;
            }
        }
        catch (JsonException)
        {
            // Not JSON after all: nothing to screen
        }
        return result;
    }

    private static string? ContentText(JsonElement content)
    {
        if (content.ValueKind == JsonValueKind.String)
        {
            return content.GetString();
        }
        if (content.ValueKind != JsonValueKind.Array)
        {
            return null;
        }
        var parts = new StringBuilder();
        foreach (var part in content.EnumerateArray())
        {
            if (part.ValueKind == JsonValueKind.Object
                && part.TryGetProperty("text", out var text) && text.ValueKind == JsonValueKind.String)
            {
                if (parts.Length > 0)
                {
                    parts.Append('\n');
                }
                parts.Append(text.GetString());
            }
        }
        return parts.Length > 0 ? parts.ToString() : null;
    }
}
