using System.Collections.Concurrent;
using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace LlmGuard.Tests;

/// <summary>One /v1/check call as the fake gateway received it.</summary>
public sealed record GatewayCall(string Path, string? ApiKey, string Text, string Source);

/// <summary>
/// Fake security gateway. By default blocks any text containing "ignore all previous
/// instructions" and allows everything else; <see cref="Respond"/> overrides that.
/// </summary>
public sealed class FakeGateway : HttpMessageHandler
{
    public ConcurrentQueue<GatewayCall> Calls { get; } = new();

    /// <summary>Custom behaviour: return a response, or throw to simulate a network error.</summary>
    public Func<GatewayCall, CancellationToken, Task<HttpResponseMessage>>? Respond { get; set; }

    public static HttpResponseMessage Verdict(string verdict, double score = 0.5, string layer = "classifier", double latencyMs = 12.5) =>
        Json($$"""{"verdict":"{{verdict}}","score":{{score.ToString(System.Globalization.CultureInfo.InvariantCulture)}},"layer":"{{layer}}","latency_ms":{{latencyMs.ToString(System.Globalization.CultureInfo.InvariantCulture)}}}""");

    public static HttpResponseMessage Json(string body, HttpStatusCode status = HttpStatusCode.OK) =>
        new(status) { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        using var doc = JsonDocument.Parse(await request.Content!.ReadAsStringAsync(cancellationToken));
        var call = new GatewayCall(
            request.RequestUri!.AbsolutePath,
            request.Headers.TryGetValues("X-API-Key", out var keys) ? keys.Single() : null,
            doc.RootElement.GetProperty("text").GetString()!,
            doc.RootElement.GetProperty("source").GetString()!);
        Calls.Enqueue(call);

        if (Respond is not null)
        {
            return await Respond(call, cancellationToken);
        }
        return call.Text.Contains("ignore all previous instructions", StringComparison.OrdinalIgnoreCase)
            ? Verdict("block", 0.97, "classifier")
            : Verdict("allow", 0.02, "classifier");
    }

    /// <summary>Simulates a gateway that never answers in time.</summary>
    public static async Task<HttpResponseMessage> Hang(GatewayCall _, CancellationToken ct)
    {
        await Task.Delay(TimeSpan.FromSeconds(30), ct);
        return Verdict("allow");
    }
}

/// <summary>Records every inner request a DelegatingHandler forwards.</summary>
public sealed class RecordingInnerHandler : HttpMessageHandler
{
    public List<string> Bodies { get; } = new();

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        Bodies.Add(request.Content is null ? "" : await request.Content.ReadAsStringAsync(cancellationToken));
        return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("{}") };
    }
}

/// <summary>Captures formatted log messages and their structured state.</summary>
public sealed class CapturingLoggerProvider : ILoggerProvider
{
    public ConcurrentQueue<(LogLevel Level, string Message, IReadOnlyList<KeyValuePair<string, object?>> State)> Entries { get; } = new();

    public ILogger CreateLogger(string categoryName) => new Logger(this);

    public void Dispose() { }

    public string AllText => string.Join("\n", Entries.Select(e =>
        e.Message + " " + string.Join(" ", e.State.Select(kv => $"{kv.Key}={kv.Value}"))));

    private sealed class Logger(CapturingLoggerProvider owner) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            // Snapshot now: framework log states can reference an HttpContext that is disposed later
            var kvs = (state as IReadOnlyList<KeyValuePair<string, object?>> ?? Array.Empty<KeyValuePair<string, object?>>())
                .Select(kv => new KeyValuePair<string, object?>(kv.Key, kv.Value?.ToString()))
                .ToList();
            owner.Entries.Enqueue((logLevel, formatter(state, exception), kvs));
        }
    }
}

public static class Make
{
    public const string ApiKey = "unit-test-key";

    public static LlmGuardOptions Options(FailMode failMode = FailMode.FailClosed, int timeoutMs = 2000) => new()
    {
        GatewayUrl = new Uri("http://gateway.test"),
        ApiKey = ApiKey,
        Timeout = TimeSpan.FromMilliseconds(timeoutMs),
        FailMode = failMode,
        ProtectedRoutes = { "/chat" },
    };

    public static ILlmGuardClient Client(FakeGateway gateway, LlmGuardOptions? options = null, CapturingLoggerProvider? logs = null)
    {
        var http = new HttpClient(gateway) { BaseAddress = new Uri("http://gateway.test/"), Timeout = Timeout.InfiniteTimeSpan };
        ILogger<LlmGuardClient> logger = logs is null
            ? NullLogger<LlmGuardClient>.Instance
            : new LoggerFactory(new[] { logs }).CreateLogger<LlmGuardClient>();
        return new LlmGuardClient(http, Microsoft.Extensions.Options.Options.Create(options ?? Options()), logger);
    }
}
