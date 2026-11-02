using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace LlmGuard;

/// <summary>
/// <see cref="DelegatingHandler"/> for HttpClients that call LLM providers. Before an
/// OpenAI-compatible request leaves the app, the content of every message in
/// <c>messages</c> (and a top-level <c>prompt</c>, for completion-style APIs) is screened.
/// Messages are checked concurrently. If any is blocked the request is not sent and
/// <see cref="LlmGuardBlockedException"/> is thrown; under <see cref="FailMode.FailClosed"/>
/// an unscreenable message throws <see cref="LlmGuardUnavailableException"/>.
/// POST/PUT/PATCH on this explicitly registered client are protected. Other methods pass through.
/// </summary>
public sealed class LlmGuardHandler : DelegatingHandler
{
    private readonly ILlmGuardClient _guard;
    private readonly ILogger<LlmGuardHandler> _logger;
    private readonly LlmGuardOptions _options;

    /// <summary>Created by <c>AddLlmGuardHandler()</c>.</summary>
    public LlmGuardHandler(ILlmGuardClient guard, ILogger<LlmGuardHandler> logger)
        : this(guard, logger, Options.Create(new LlmGuardOptions())) { }

    /// <summary>Created by DI with the configured payload bound and failure mode.</summary>
    public LlmGuardHandler(ILlmGuardClient guard, ILogger<LlmGuardHandler> logger, IOptions<LlmGuardOptions> options)
    {
        _guard = guard;
        _logger = logger;
        _options = options.Value;
    }

    /// <inheritdoc />
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        if (request.Method != HttpMethod.Post && request.Method != HttpMethod.Put && request.Method != HttpMethod.Patch)
        {
            return await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
        }

        cancellationToken.ThrowIfCancellationRequested();
        if (request.Content is null)
        {
            RequireInspection(InspectionOutcome.MissingContent);
            return await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
        }
        var supportedType = LooksLikeJson(request.Content) && request.Content.Headers.ContentEncoding.Count == 0;
        if (request.Content.Headers.ContentLength > _options.MaxBodyBytes)
            RequireInspection(InspectionOutcome.OversizedPayload, alwaysReject: true);

        byte[] body;
        try
        {
            var stream = await request.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
            body = await PayloadInspection.ReadAsync(stream, _options.MaxBodyBytes, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or HttpRequestException or NotSupportedException)
        {
            // A partially consumed body cannot safely be forwarded, even in legacy mode.
            RequireInspection(InspectionOutcome.ExtractionFailure, alwaysReject: true);
            throw; // RequireInspection always throws above.
        }
        if (body.Length > _options.MaxBodyBytes)
            RequireInspection(InspectionOutcome.OversizedPayload, alwaysReject: true);

        var original = request.Content;
        var buffered = new ByteArrayContent(body);
        foreach (var header in original.Headers)
            buffered.Headers.TryAddWithoutValidation(header.Key, header.Value);
        request.Content = buffered;
        original.Dispose();

        if (!supportedType)
        {
            RequireInspection(InspectionOutcome.UnexpectedContentType);
            return await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
        }
        var messages = ChatPayload.ExtractMessages(body, out var inspection);
        if (inspection != InspectionOutcome.Inspected)
        {
            RequireInspection(inspection);
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
        cancellationToken.ThrowIfCancellationRequested();
        return await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
    }

    private void RequireInspection(InspectionOutcome reason, bool alwaysReject = false)
    {
        var outcome = !alwaysReject && _options.FailMode == FailMode.FailOpen
            ? GuardOutcome.FailedOpen : GuardOutcome.FailedClosed;
        Log.InspectionFailed(_logger, outcome, reason.ToString());
        if (outcome == GuardOutcome.FailedClosed)
            throw new LlmGuardUnavailableException(new GuardDecision(outcome, null, null, null, 0,
                reason.ToString()), -1, null);
    }

    private static bool LooksLikeJson(HttpContent content)
    {
        var mediaType = content.Headers.ContentType?.MediaType;
        return PayloadInspection.IsJson(mediaType, content.Headers.ContentType?.CharSet);
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
    public static IReadOnlyList<Message> ExtractMessages(byte[] body, out InspectionOutcome outcome)
    {
        var result = new List<Message>();
        outcome = InspectionOutcome.MissingContent;
        if (body.Length == 0)
        {
            return result;
        }
        try
        {
            using var document = JsonDocument.Parse(body);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object || PayloadInspection.HasDuplicateProperties(root))
            {
                outcome = InspectionOutcome.UnsupportedFormat;
                return result;
            }
            if (root.TryGetProperty("input", out _))
            {
                outcome = InspectionOutcome.UnsupportedFormat;
                return result;
            }
            if (root.TryGetProperty("prompt", out var prompt))
            {
                if (prompt.ValueKind != JsonValueKind.String || string.IsNullOrWhiteSpace(prompt.GetString()))
                {
                    outcome = InspectionOutcome.UnsupportedFormat;
                    return result;
                }
                var promptText = prompt.GetString()!;
                result.Add(new Message(-1, null, "user", promptText));
            }
            if (!root.TryGetProperty("messages", out var messages))
            {
                outcome = result.Count > 0 ? InspectionOutcome.Inspected : InspectionOutcome.MissingContent;
                return result;
            }
            if (messages.ValueKind != JsonValueKind.Array || messages.GetArrayLength() == 0)
            {
                outcome = InspectionOutcome.UnsupportedFormat;
                return result;
            }
            var index = 0;
            foreach (var message in messages.EnumerateArray())
            {
                if (message.ValueKind != JsonValueKind.Object
                    || message.TryGetProperty("tool_calls", out _) || message.TryGetProperty("function_call", out _))
                {
                    outcome = InspectionOutcome.UnsupportedFormat;
                    return result;
                }
                var role = message.TryGetProperty("role", out var r) && r.ValueKind == JsonValueKind.String
                    ? r.GetString() : null;
                var text = message.TryGetProperty("content", out var content) ? ContentText(content) : null;
                if (role is not ("user" or "system" or "assistant" or "tool" or "function" or "developer")
                    || string.IsNullOrWhiteSpace(text))
                {
                    outcome = InspectionOutcome.UnsupportedFormat;
                    return result;
                }
                var source = role is "tool" or "function" ? "rag" : "user";
                result.Add(new Message(index, role, source, text));
                index++;
            }
        }
        catch (JsonException)
        {
            outcome = InspectionOutcome.InvalidJson;
            return result;
        }
        outcome = result.Count > 0 ? InspectionOutcome.Inspected : InspectionOutcome.MissingContent;
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
                && part.TryGetProperty("type", out var type) && type.ValueKind == JsonValueKind.String
                && type.GetString() == "text"
                && part.TryGetProperty("text", out var text) && text.ValueKind == JsonValueKind.String
                && !string.IsNullOrWhiteSpace(text.GetString()))
            {
                if (parts.Length > 0)
                {
                    parts.Append('\n');
                }
                parts.Append(text.GetString());
            }
            else return null;
        }
        return parts.Length > 0 ? parts.ToString() : null;
    }
}
