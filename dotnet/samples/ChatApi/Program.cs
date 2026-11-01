// Sample: a chat API protected by LlmGuard in both directions.
//
//   1. app.UseLlmGuard()       screens the incoming "prompt" on POST /chat
//   2. AddLlmGuardHandler()    screens every message (history included) before the
//                              request to the LLM provider leaves the app
//
// The gateway API key comes from configuration or the environment, never from code:
//   setx LLMGUARD_API_KEY <key>        (or: dotnet user-secrets set LlmGuard:ApiKey <key>)
//
// With no Llm:BaseUrl configured, a fake in-process provider echoes the prompt, so the
// sample runs without an OpenAI key.

using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json.Serialization;
using ChatApi;
using LlmGuard;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddLlmGuard();

var llm = builder.Services.AddHttpClient("llm", (sp, http) =>
    {
        var config = sp.GetRequiredService<IConfiguration>();
        var baseUrl = config["Llm:BaseUrl"];
        http.BaseAddress = new Uri(string.IsNullOrEmpty(baseUrl) ? "http://fake-llm.local/" : baseUrl.TrimEnd('/') + "/");
        if (config["Llm:ApiKey"] is { Length: > 0 } key)
        {
            http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", key);
        }
    })
    .AddLlmGuardHandler();
if (string.IsNullOrEmpty(builder.Configuration["Llm:BaseUrl"]))
{
    llm.ConfigurePrimaryHttpMessageHandler(() => new FakeLlmHandler());
}

var app = builder.Build();

app.UseLlmGuard();

app.MapGet("/health", () => Results.Ok(new { status = "ok" }));

app.MapPost("/chat", async (ChatRequest request, IHttpClientFactory factory, IConfiguration config, CancellationToken ct) =>
{
    var messages = new List<ChatMessage> { new("system", "You are a helpful assistant.") };
    messages.AddRange(request.History ?? []);
    messages.Add(new ChatMessage("user", request.Prompt));

    try
    {
        var client = factory.CreateClient("llm");
        using var response = await client.PostAsJsonAsync("v1/chat/completions",
            new ChatCompletionRequest(config["Llm:Model"] ?? "gpt-4o-mini", messages), ct);
        response.EnsureSuccessStatusCode();
        var completion = await response.Content.ReadFromJsonAsync<ChatCompletionResponse>(ct);
        return Results.Ok(new { reply = completion?.Choices.FirstOrDefault()?.Message.Content });
    }
    catch (LlmGuardBlockedException ex)
    {
        // A message in the conversation (e.g. pasted history) was blocked on the way out
        return Results.Json(new { error = "prompt_blocked", reason = "A message in the conversation was blocked by the LLM security gateway.",
                                  layer = ex.Decision.Layer, message_index = ex.MessageIndex },
                            statusCode: StatusCodes.Status403Forbidden);
    }
    catch (LlmGuardUnavailableException)
    {
        return Results.Json(new { error = "guard_unavailable", reason = "The conversation could not be screened." },
                            statusCode: StatusCodes.Status503ServiceUnavailable);
    }
});

app.Run();

namespace ChatApi
{
    public sealed record ChatRequest(string Prompt, List<ChatMessage>? History);

    public sealed record ChatMessage(
        [property: JsonPropertyName("role")] string Role,
        [property: JsonPropertyName("content")] string Content);

    public sealed record ChatCompletionRequest(
        [property: JsonPropertyName("model")] string Model,
        [property: JsonPropertyName("messages")] List<ChatMessage> Messages);

    public sealed record ChatCompletionResponse(
        [property: JsonPropertyName("choices")] List<ChatChoice> Choices);

    public sealed record ChatChoice(
        [property: JsonPropertyName("message")] ChatMessage Message);

    /// <summary>Stand-in OpenAI-compatible provider: echoes the last user message.</summary>
    public sealed class FakeLlmHandler : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var body = await request.Content!.ReadFromJsonAsync<ChatCompletionRequest>(cancellationToken);
            var last = body?.Messages.LastOrDefault(m => m.Role == "user")?.Content ?? "";
            var reply = new ChatCompletionResponse([new ChatChoice(new ChatMessage("assistant", $"(fake LLM) You said: {last}"))]);
            return new HttpResponseMessage(System.Net.HttpStatusCode.OK) { Content = JsonContent.Create(reply) };
        }
    }
}

/// <summary>Exposed for WebApplicationFactory in the tests.</summary>
public partial class Program;
