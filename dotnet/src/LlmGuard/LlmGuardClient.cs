using System.Diagnostics;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace LlmGuard;

/// <summary>Screens text through the security gateway's <c>POST /v1/check</c>.</summary>
public interface ILlmGuardClient
{
    /// <summary>
    /// Screens <paramref name="text"/>. Never throws for gateway problems: timeouts,
    /// connection errors, non-2xx replies and malformed bodies become
    /// <see cref="GuardOutcome.FailedOpen"/> or <see cref="GuardOutcome.FailedClosed"/>
    /// according to <see cref="LlmGuardOptions.FailMode"/>. Cancellation by the caller
    /// still throws <see cref="OperationCanceledException"/>.
    /// </summary>
    /// <param name="text">The prompt or message content.</param>
    /// <param name="source"><c>user</c> or <c>rag</c> (retrieved or tool content).</param>
    /// <param name="cancellationToken">Caller cancellation.</param>
    Task<GuardDecision> CheckAsync(string text, string source, CancellationToken cancellationToken = default);
}

/// <summary>Default <see cref="ILlmGuardClient"/>, used as a typed HttpClient.</summary>
internal sealed class LlmGuardClient : ILlmGuardClient
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    private readonly HttpClient _http;
    private readonly LlmGuardOptions _options;
    private readonly ILogger<LlmGuardClient> _logger;

    public LlmGuardClient(HttpClient http, IOptions<LlmGuardOptions> options, ILogger<LlmGuardClient> logger)
    {
        _http = http;
        _options = options.Value;
        _logger = logger;
    }

    public async Task<GuardDecision> CheckAsync(string text, string source, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(text);
        cancellationToken.ThrowIfCancellationRequested();
        var stopwatch = Stopwatch.StartNew();
        using var timeout = new CancellationTokenSource(_options.Timeout);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeout.Token);

        string failure;
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, "v1/check")
            {
                Content = JsonContent.Create(new CheckRequest(text, source), options: Json),
            };
            request.Headers.Add("X-API-Key", _options.ApiKey);

            using var response = await _http.SendAsync(request, linked.Token).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                failure = $"gateway returned HTTP {(int)response.StatusCode}";
            }
            else
            {
                var body = await response.Content.ReadFromJsonAsync<CheckResponse>(Json, linked.Token).ConfigureAwait(false);
                if (TryParse(body, out var outcome, out failure))
                {
                    var decision = new GuardDecision(outcome, body!.Score, body.Layer, body.LatencyMs,
                        stopwatch.Elapsed.TotalMilliseconds, null);
                    Log.Checked(_logger, decision.Outcome, decision.Layer, decision.Score, decision.GatewayLatencyMs,
                        Math.Round(decision.ElapsedMs, 2), source, text.Length, PromptFingerprint.Sha256(text));
                    return decision;
                }
            }
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            failure = $"timed out after {_options.Timeout.TotalMilliseconds:0} ms";
        }
        catch (HttpRequestException ex)
        {
            failure = $"gateway unreachable ({ex.HttpRequestError})";
        }
        catch (JsonException)
        {
            failure = "malformed gateway response (invalid JSON)";
        }
        catch (NotSupportedException)
        {
            failure = "malformed gateway response (unexpected content type)";
        }
        catch (IOException)
        {
            failure = "gateway response could not be read";
        }

        var failed = new GuardDecision(
            _options.FailMode == FailMode.FailOpen ? GuardOutcome.FailedOpen : GuardOutcome.FailedClosed,
            null, null, null, stopwatch.Elapsed.TotalMilliseconds, failure);
        Log.NoVerdict(_logger, failed.Outcome, failure, Math.Round(failed.ElapsedMs, 2), source, text.Length,
            PromptFingerprint.Sha256(text));
        return failed;
    }

    private static bool TryParse(CheckResponse? body, out GuardOutcome outcome, out string failure)
    {
        outcome = default;
        failure = "";
        if (body is null)
        {
            failure = "malformed gateway response (empty body)";
            return false;
        }
        switch (body.Verdict)
        {
            case "allow": outcome = GuardOutcome.Allowed; break;
            case "block": outcome = GuardOutcome.Blocked; break;
            default:
                failure = body.Verdict is null
                    ? "malformed gateway response (missing verdict)"
                    : "malformed gateway response (unknown verdict)";
                return false;
        }
        if (body.Score is not { } score || double.IsNaN(score) || score < 0 || score > 1)
        {
            failure = "malformed gateway response (missing or out-of-range score)";
            return false;
        }
        if (string.IsNullOrEmpty(body.Layer))
        {
            failure = "malformed gateway response (missing layer)";
            return false;
        }
        if (body.Layer is not ("rules" or "fuzzy" or "classifier" or "judge")
            || body.LatencyMs is not { } latency || !double.IsFinite(latency) || latency < 0)
        {
            failure = "malformed gateway response (invalid metadata)";
            return false;
        }
        return true;
    }

    private sealed record CheckRequest(
        [property: JsonPropertyName("text")] string Text,
        [property: JsonPropertyName("source")] string Source);

    private sealed record CheckResponse(
        [property: JsonPropertyName("verdict")] string? Verdict,
        [property: JsonPropertyName("score")] double? Score,
        [property: JsonPropertyName("layer")] string? Layer,
        [property: JsonPropertyName("latency_ms")] double? LatencyMs);
}
