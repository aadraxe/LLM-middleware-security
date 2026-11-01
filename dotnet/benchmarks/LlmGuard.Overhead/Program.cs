// Measures what LlmGuardMiddleware adds per request, against a real running gateway.
//
//   GATEWAY_API_KEYS=bench-key uvicorn app.main:app --port 8000     (repo root, separate shell)
//   LLMGUARD_API_KEY=bench-key dotnet run -c Release --project dotnet/benchmarks/LlmGuard.Overhead -- [gatewayUrl] [n]
//
// The app under test runs in memory (TestServer) with two identical endpoints: /guarded
// (behind the middleware) and /plain (not). For each prompt both are called, interleaved,
// and a timing handler on the gateway HttpClient records the HTTP round trip to the gateway
// and the gateway's own reported latency_ms. Per request:
//
//   added_total        = t(/guarded) − t(/plain)       everything the middleware adds
//   gateway_processing = latency_ms                    the gateway's own work (pipeline)
//   gateway_transport  = round trip − latency_ms       HTTP, JSON, uvicorn
//   middleware_only    = added_total − round trip      .NET work: buffering, JSON parse,
//                                                      hashing, logging, decision

using System.Diagnostics;
using System.Text;
using System.Text.Json;
using LlmGuard;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

var gatewayUrl = args.Length > 0 ? args[0] : "http://127.0.0.1:8000";
var count = args.Length > 1 ? int.Parse(args[1]) : 300;
const int warmup = 20;

var repoRoot = FindRepoRoot();
var prompts = LoadPrompts(repoRoot, count + warmup);
Console.WriteLine($"gateway {gatewayUrl}, {prompts.Count - warmup} measured requests (+{warmup} warm-up)");

var timing = new GatewayTiming();
using var host = await new HostBuilder()
    .ConfigureWebHost(web => web
        .UseTestServer()
        .ConfigureLogging(l => l.ClearProviders().AddProvider(new FormattingNullLoggerProvider()).SetMinimumLevel(LogLevel.Information))
        .ConfigureServices(services =>
        {
            services.AddRouting();
            services.AddLlmGuard(o =>
            {
                o.GatewayUrl = new Uri(gatewayUrl);
                o.ProtectedRoutes.Add("/guarded");
                o.Timeout = TimeSpan.FromSeconds(10);
            });
            services.AddHttpClient(LlmGuardDefaults.GatewayHttpClientName).AddHttpMessageHandler(() => timing);
        })
        .Configure(app =>
        {
            app.UseLlmGuard();
            app.UseRouting();
            app.UseEndpoints(e =>
            {
                e.MapPost("/guarded", () => Results.Ok());
                e.MapPost("/plain", () => Results.Ok());
            });
        }))
    .StartAsync();
var client = host.GetTestClient();

var rows = new List<(double Added, double RoundTrip, double Gateway, double Plain)>();
var blocked = 0;
for (var i = 0; i < prompts.Count; i++)
{
    var body = JsonSerializer.Serialize(new { prompt = prompts[i] });

    var plain = await Time(() => client.PostAsync("/plain", Json(body)));
    timing.Reset();
    var (guarded, status) = await TimeWithStatus(() => client.PostAsync("/guarded", Json(body)));
    if (timing.RoundTripMs is not { } roundTrip || timing.GatewayLatencyMs is not { } gateway)
    {
        throw new InvalidOperationException($"request {i}: the gateway was not called (status {status})");
    }
    if (i < warmup)
    {
        continue;
    }
    if (status == 403)
    {
        blocked++;
    }
    else if (status != 200)
    {
        throw new InvalidOperationException($"request {i}: unexpected status {status}");
    }
    rows.Add((guarded - plain, roundTrip, gateway, plain));
}

Console.WriteLine($"{rows.Count} requests, {blocked} blocked by the gateway\n");
Console.WriteLine($"{"per request (ms)",-34} {"mean",8} {"p50",8} {"p95",8}");
Report("added by middleware, total", rows.Select(r => r.Added));
Report("  gateway processing (latency_ms)", rows.Select(r => r.Gateway));
Report("  gateway transport (HTTP, JSON)", rows.Select(r => r.RoundTrip - r.Gateway));
Report("  middleware itself (.NET side)", rows.Select(r => r.Added - r.RoundTrip));
Report("unguarded request (baseline)", rows.Select(r => r.Plain));

static void Report(string label, IEnumerable<double> values)
{
    var v = values.OrderBy(x => x).ToArray();
    Console.WriteLine($"{label,-34} {v.Average(),8:0.00} {v[v.Length / 2],8:0.00} {v[(int)(v.Length * 0.95)],8:0.00}");
}

static StringContent Json(string body) => new(body, Encoding.UTF8, "application/json");

static async Task<double> Time(Func<Task<HttpResponseMessage>> send) => (await TimeWithStatus(send)).Ms;

static async Task<(double Ms, int Status)> TimeWithStatus(Func<Task<HttpResponseMessage>> send)
{
    var sw = Stopwatch.StartNew();
    using var response = await send();
    sw.Stop();
    return (sw.Elapsed.TotalMilliseconds, (int)response.StatusCode);
}

static string FindRepoRoot()
{
    var dir = new DirectoryInfo(AppContext.BaseDirectory);
    while (dir is not null && !Directory.Exists(Path.Combine(dir.FullName, "data", "processed")))
    {
        dir = dir.Parent;
    }
    return dir?.FullName ?? throw new DirectoryNotFoundException("repo root with data/processed not found");
}

static List<string> LoadPrompts(string root, int needed)
{
    // deepset benchmark (committed) first, then the held-out test split if it has been built
    var prompts = new List<string>();
    foreach (var file in new[] { "benchmark_200.jsonl", "test.jsonl" })
    {
        var path = Path.Combine(root, "data", "processed", file);
        if (!File.Exists(path))
        {
            continue;
        }
        foreach (var line in File.ReadLines(path))
        {
            if (prompts.Count == needed)
            {
                return prompts;
            }
            prompts.Add(JsonDocument.Parse(line).RootElement.GetProperty("text").GetString()!);
        }
    }
    while (prompts.Count < needed)
    {
        prompts.Add(prompts[prompts.Count % 200]);
    }
    return prompts;
}

/// <summary>Records the gateway round trip and the latency_ms the gateway reports.</summary>
sealed class GatewayTiming : DelegatingHandler
{
    public double? RoundTripMs { get; private set; }
    public double? GatewayLatencyMs { get; private set; }

    public void Reset() => (RoundTripMs, GatewayLatencyMs) = (null, null);

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var sw = Stopwatch.StartNew();
        var response = await base.SendAsync(request, cancellationToken);
        await response.Content.LoadIntoBufferAsync();
        sw.Stop();
        RoundTripMs = sw.Elapsed.TotalMilliseconds;
        var json = await response.Content.ReadAsStringAsync(cancellationToken);
        if (response.IsSuccessStatusCode)
        {
            GatewayLatencyMs = JsonDocument.Parse(json).RootElement.GetProperty("latency_ms").GetDouble();
        }
        return response;
    }
}

/// <summary>Formats every message (so logging cost is included) but writes nowhere.</summary>
sealed class FormattingNullLoggerProvider : ILoggerProvider
{
    public ILogger CreateLogger(string categoryName) => new Logger();
    public void Dispose() { }

    sealed class Logger : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => logLevel >= LogLevel.Information;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
            => GC.KeepAlive(formatter(state, exception));
    }
}
