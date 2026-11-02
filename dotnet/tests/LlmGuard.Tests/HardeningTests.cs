using System.Net;
using System.Net.Http.Json;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.Http;

namespace LlmGuard.Tests;

public class HardeningTests
{
    private static (HttpClient Client, RecordingInnerHandler Inner) Outgoing(FakeGateway gateway,
        LlmGuardOptions? options = null, CapturingLoggerProvider? logs = null)
    {
        options ??= Make.Options(timeoutMs: 100);
        var inner = new RecordingInnerHandler();
        var logger = logs is null ? Microsoft.Extensions.Logging.Abstractions.NullLogger<LlmGuardHandler>.Instance
            : (ILogger<LlmGuardHandler>)new LoggerFactory(new[] { logs }).CreateLogger<LlmGuardHandler>();
        var handler = new LlmGuardHandler(Make.Client(gateway, options, logs), logger, Options.Create(options))
            { InnerHandler = inner };
        return (new HttpClient(handler) { BaseAddress = new Uri("https://provider.test/") }, inner);
    }

    [Fact]
    public void Default_is_closed() => Assert.Equal(FailMode.FailClosed, new LlmGuardOptions().FailMode);

    [Theory]
    [InlineData("{}", "application/json")]
    [InlineData("[]", "application/json")]
    [InlineData("{broken", "application/json")]
    [InlineData("{\"prompt\":\"secret\"}", "text/plain")]
    [InlineData("{\"prompt\":\"\"}", "application/json")]
    [InlineData("{\"prompt\":null}", "application/json")]
    [InlineData("{\"prompt\":\"safe\",\"Prompt\":\"secret\"}", "application/json")]
    public async Task Incoming_unscreenable_executes_zero(string body, string type)
    {
        var (client, gateway, host, seen) = await LlmGuardMiddlewareTests.Start();
        using var owner = host;
        using var response = await client.PostAsync("/chat", new StringContent(body, Encoding.UTF8, type));
        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Contains("payload_unscreenable", await response.Content.ReadAsStringAsync());
        Assert.Empty(seen);
        Assert.Empty(gateway.Calls);
    }

    [Theory]
    [InlineData("{}")]
    [InlineData("[]")]
    [InlineData("{broken")]
    [InlineData("{\"messages\":[{\"role\":\"user\",\"content\":\"ok\"},42]}")]
    [InlineData("{\"messages\":[{\"role\":\"user\",\"content\":[{\"type\":\"text\",\"text\":\"ok\"},{\"type\":\"image_url\",\"image_url\":{\"url\":\"secret\"}}]}]}")]
    [InlineData("{\"messages\":[{\"role\":\"tool\",\"content\":null}]}")]
    [InlineData("{\"messages\":[{\"role\":\"user\",\"content\":[[{\"type\":\"text\",\"text\":\"secret\"}]]}]}")]
    [InlineData("{\"prompt\":\"safe\",\"input\":\"secret\"}")]
    [InlineData("{\"prompt\":\"safe\",\"prompt\":\"secret\"}")]
    [InlineData("{\"messages\":[{\"role\":\"assistant\",\"content\":\"ok\",\"tool_calls\":[]}]}")]
    [InlineData("{\"messages\":[{\"role\":\"user\"}]}")]
    public async Task Outgoing_unscreenable_executes_zero(string body)
    {
        var gateway = new FakeGateway();
        var (client, inner) = Outgoing(gateway);
        using var owner = client;
        var ex = await Assert.ThrowsAsync<LlmGuardUnavailableException>(() =>
            client.PostAsync("chat", new StringContent(body, Encoding.UTF8, "application/json")));
        Assert.Equal(GuardOutcome.FailedClosed, ex.Decision.Outcome);
        Assert.Empty(inner.Bodies);
        Assert.Empty(gateway.Calls); // never partially screen a malformed conversation
    }

    [Theory]
    [InlineData("text/plain")]
    [InlineData("application/json; charset=utf-16")]
    public async Task Outgoing_content_type_is_enforced(string type)
    {
        var (client, inner) = Outgoing(new FakeGateway());
        using var owner = client;
        using var content = new ByteArrayContent(Encoding.UTF8.GetBytes("{\"prompt\":\"hello\"}"));
        content.Headers.ContentType = System.Net.Http.Headers.MediaTypeHeaderValue.Parse(type);
        await Assert.ThrowsAsync<LlmGuardUnavailableException>(() => client.PostAsync("chat", content));
        Assert.Empty(inner.Bodies);
    }

    [Fact]
    public async Task Outgoing_missing_body_is_unavailable()
    {
        var (client, inner) = Outgoing(new FakeGateway());
        using var owner = client;
        await Assert.ThrowsAsync<LlmGuardUnavailableException>(() => client.PostAsync("chat", null));
        Assert.Empty(inner.Bodies);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Outgoing_size_bound_applies_even_to_legacy_streams(bool legacy)
    {
        var options = Make.Options(legacy ? FailMode.FailOpen : FailMode.FailClosed);
        options.MaxBodyBytes = 20;
        var (client, inner) = Outgoing(new FakeGateway(), options);
        using var owner = client;
        using var content = new StreamContent(new MemoryStream(Encoding.UTF8.GetBytes(new string('x', 100))));
        content.Headers.ContentType = new("application/json");
        await Assert.ThrowsAsync<LlmGuardUnavailableException>(() => client.PostAsync("chat", content));
        Assert.Empty(inner.Bodies);
    }

    [Theory]
    [InlineData(401)]
    [InlineData(403)]
    [InlineData(500)]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(-2)]
    [InlineData(-3)]
    [InlineData(-4)]
    public async Task Gateway_failure_executes_zero_at_both_boundaries(int kind)
    {
        var gateway = new FakeGateway { Respond = (_, ct) => kind switch
        {
            0 => throw new HttpRequestException("synthetic-sensitive-error"),
            -1 => Task.FromResult(FakeGateway.Json("{broken")),
            -2 => Task.FromResult(FakeGateway.Verdict("undefined")),
            -3 => FakeGateway.Hang(new GatewayCall("", null, "", "user"), ct),
            -4 => Task.FromResult(FakeGateway.Json("{\"score\":0.1,\"layer\":\"classifier\",\"latency_ms\":1}")),
            _ => Task.FromResult(FakeGateway.Json("synthetic-secret-body", (HttpStatusCode)kind)),
        }};
        var (incoming, _, host, seen) = await LlmGuardMiddlewareTests.Start(gateway: gateway);
        using var hostOwner = host;
        using var response = await incoming.PostAsJsonAsync("/chat", new { prompt = "hello" });
        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Empty(seen);
        var (outgoing, inner) = Outgoing(gateway);
        using var clientOwner = outgoing;
        await Assert.ThrowsAsync<LlmGuardUnavailableException>(() => outgoing.PostAsJsonAsync("chat", new { prompt = "hello" }));
        Assert.Empty(inner.Bodies);
    }

    [Fact]
    public async Task Legacy_unscreenable_opt_in_is_explicit_and_logged()
    {
        var logs = new CapturingLoggerProvider();
        var options = Make.Options(FailMode.FailOpen);
        var (client, inner) = Outgoing(new FakeGateway(), options, logs);
        using var owner = client;
        using var response = await client.PostAsync("chat", new StringContent("synthetic-secret"));
        Assert.Single(inner.Bodies);
        Assert.Contains("FailedOpen", logs.AllText);
        Assert.DoesNotContain("synthetic-secret", logs.AllText);
        var (incoming, _, host, seen) = await LlmGuardMiddlewareTests.Start(o => o.FailMode = FailMode.FailOpen);
        using var hostOwner = host;
        using var result = await incoming.PostAsJsonAsync("/chat", new { other = "unrecognized" });
        Assert.Equal(HttpStatusCode.OK, result.StatusCode);
        Assert.Single(seen);
    }

    [Theory]
    [InlineData(FailMode.FailClosed)]
    [InlineData(FailMode.FailOpen)]
    public async Task Cancellation_never_forwards_or_retries(FailMode mode)
    {
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var gateway = new FakeGateway { Respond = (call, ct) => { started.SetResult(); return FakeGateway.Hang(call, ct); } };
        var (client, inner) = Outgoing(gateway, Make.Options(mode, timeoutMs: 10_000));
        using var owner = client;
        using var cts = new CancellationTokenSource();
        var pending = client.PostAsJsonAsync("chat", new { prompt = "hello" }, cts.Token);
        await started.Task.WaitAsync(TimeSpan.FromSeconds(5));
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => pending);
        Assert.Empty(inner.Bodies);
        Assert.Single(gateway.Calls);
    }

    [Fact]
    public async Task All_messages_finish_before_forwarding()
    {
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var gateway = new FakeGateway { Respond = async (call, ct) =>
        {
            if (call.Text == "wait") { started.SetResult(); await release.Task.WaitAsync(ct); }
            return FakeGateway.Verdict("allow");
        }};
        var (client, inner) = Outgoing(gateway, Make.Options(timeoutMs: 10_000));
        using var owner = client;
        var pending = client.PostAsJsonAsync("chat", new { messages = new[] {
            new { role = "user", content = "ok" }, new { role = "tool", content = "wait" } } });
        await started.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Empty(inner.Bodies);
        release.SetResult();
        using var response = await pending;
        Assert.Single(inner.Bodies);
    }

    [Fact]
    public async Task Gateway_metadata_and_exceptions_cannot_leak_into_logs()
    {
        var logs = new CapturingLoggerProvider();
        var gateway = new FakeGateway { Respond = (_, _) => Task.FromResult(FakeGateway.Verdict("allow", layer: "synthetic-secret")) };
        var decision = await Make.Client(gateway, logs: logs).CheckAsync("synthetic-secret", "user");
        Assert.Equal(GuardOutcome.FailedClosed, decision.Outcome);
        gateway.Respond = (_, _) => throw new HttpRequestException("synthetic-secret" + Make.ApiKey);
        await Make.Client(gateway, logs: logs).CheckAsync("synthetic-secret", "user");
        Assert.DoesNotContain("synthetic-secret", logs.AllText);
        Assert.DoesNotContain(Make.ApiKey, logs.AllText);
    }

    [Fact]
    public async Task Unregistered_client_is_unaffected()
    {
        var inner = new RecordingInnerHandler();
        using var client = new HttpClient(inner);
        using var response = await client.PostAsync("https://unrelated.test/", new StringContent("not LLM JSON"));
        Assert.Single(inner.Bodies);
    }

    [Theory]
    [InlineData(FailMode.FailClosed)]
    [InlineData(FailMode.FailOpen)]
    public async Task Middleware_cancellation_never_executes(FailMode mode)
    {
        var context = new DefaultHttpContext();
        context.Request.Method = "POST";
        context.Request.Path = "/chat";
        context.Request.ContentType = "application/json";
        context.Request.Body = new MemoryStream(Encoding.UTF8.GetBytes("{\"prompt\":\"hello\"}"));
        using var cts = new CancellationTokenSource();
        context.RequestAborted = cts.Token;
        var next = 0;
        var options = Make.Options(mode, timeoutMs: 10_000);
        var middleware = new LlmGuardMiddleware(_ => { next++; return Task.CompletedTask; },
            Options.Create(options), Microsoft.Extensions.Logging.Abstractions.NullLogger<LlmGuardMiddleware>.Instance);
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var gateway = new FakeGateway { Respond = (call, ct) => { started.SetResult(); return FakeGateway.Hang(call, ct); } };
        var pending = middleware.InvokeAsync(context, Make.Client(gateway, options));
        await started.Task.WaitAsync(TimeSpan.FromSeconds(5));
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => pending);
        Assert.Equal(0, next);
        Assert.Single(gateway.Calls);
    }

    private sealed class ReadFailureStream : MemoryStream
    {
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
            ValueTask.FromException<int>(new IOException("synthetic-sensitive-stream-error"));
    }

    [Theory]
    [InlineData(FailMode.FailClosed)]
    [InlineData(FailMode.FailOpen)]
    public async Task Stream_read_errors_are_sanitized_and_never_forwarded(FailMode mode)
    {
        var logs = new CapturingLoggerProvider();
        var options = Make.Options(mode);
        var (outgoing, inner) = Outgoing(new FakeGateway(), options, logs);
        using var clientOwner = outgoing;
        using var content = new StreamContent(new ReadFailureStream());
        content.Headers.ContentType = new("application/json");
        var ex = await Assert.ThrowsAsync<LlmGuardUnavailableException>(() => outgoing.PostAsync("chat", content));
        Assert.Equal("ExtractionFailure", ex.Decision.FailureReason);
        Assert.Empty(inner.Bodies);
        var context = new DefaultHttpContext();
        context.Request.Method = "POST";
        context.Request.Path = "/chat";
        context.Request.ContentType = "application/json";
        context.Request.Body = new ReadFailureStream();
        context.Response.Body = new MemoryStream();
        var next = 0;
        var middleware = new LlmGuardMiddleware(_ => { next++; return Task.CompletedTask; }, Options.Create(options),
            new LoggerFactory(new[] { logs }).CreateLogger<LlmGuardMiddleware>());
        await middleware.InvokeAsync(context, Make.Client(new FakeGateway()));
        Assert.Equal(503, context.Response.StatusCode);
        Assert.Equal(0, next);
        Assert.DoesNotContain("synthetic-sensitive", logs.AllText + ex.Message);
    }

    [Fact]
    public async Task Legacy_non_json_body_still_has_a_size_limit()
    {
        var options = Make.Options(FailMode.FailOpen);
        options.MaxBodyBytes = 10;
        var (outgoing, inner) = Outgoing(new FakeGateway(), options);
        using var clientOwner = outgoing;
        await Assert.ThrowsAsync<LlmGuardUnavailableException>(() =>
            outgoing.PostAsync("chat", new StringContent(new string('x', 100))));
        Assert.Empty(inner.Bodies);
        var (incoming, _, host, seen) = await LlmGuardMiddlewareTests.Start(o =>
        { o.FailMode = FailMode.FailOpen; o.MaxBodyBytes = 10; });
        using var hostOwner = host;
        using var response = await incoming.PostAsync("/chat", new StringContent(new string('x', 100)));
        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, response.StatusCode);
        Assert.Empty(seen);
    }
}
