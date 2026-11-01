# LlmGuard for .NET

ASP.NET Core middleware and an `HttpClient` handler that route an app's LLM traffic through the [LLM security gateway](../README.md) in this repository. Prompts are screened for jailbreaks and prompt injection before they reach your endpoint or leave for an LLM provider.

- **`LlmGuardMiddleware`** screens incoming requests on routes you choose (e.g. `POST /chat`). It reads the prompt from a JSON field. Blocked prompts get **403** and never reach your endpoint.
- **`LlmGuardHandler`** is a `DelegatingHandler` for the `HttpClient` that calls your LLM provider. In OpenAI-compatible chat requests it screens **every message** (history, system and tool messages included) before the request leaves the app.

Targets .NET 8 (`net8.0`). It has no package dependencies beyond the ASP.NET Core shared framework.

## Setup

1. **Run the gateway** with at least one API key (from the repo root):

   ```bash
   export GATEWAY_API_KEYS="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"   # keep this value
   uvicorn app.main:app --port 8000
   ```

2. **Reference the package.** It isn't published; build it locally and add the output folder as a package source:

   ```bash
   cd dotnet
   dotnet pack src/LlmGuard -c Release -o artifacts
   dotnet nuget add source "$(pwd)/artifacts" --name llmguard-local    # once
   dotnet add <YourApp>.csproj package LlmGuard --version 0.1.0
   ```

   Or reference `src/LlmGuard/LlmGuard.csproj` directly.

3. **Configure it.** Settings go in `appsettings.json`; the API key goes in the environment or user secrets, never in source or appsettings:

   ```json
   "LlmGuard": {
     "GatewayUrl": "http://localhost:8000",
     "Timeout": "00:00:02",
     "ProtectedRoutes": [ "/chat" ],
     "PromptJsonField": "prompt",
     "FailMode": "FailOpen"
   }
   ```

   ```bash
   export LLMGUARD_API_KEY=<a key from GATEWAY_API_KEYS>      # or LlmGuard__ApiKey
   dotnet user-secrets set LlmGuard:ApiKey <key>               # development
   ```

## Usage

```csharp
using LlmGuard;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddLlmGuard();                       // binds the "LlmGuard" section, validates at startup

builder.Services.AddHttpClient("openai", c => c.BaseAddress = new Uri("https://api.openai.com/"))
    .AddLlmGuardHandler();                            // screens outgoing chat messages

var app = builder.Build();
app.UseLlmGuard();                                    // screens POST /chat (from ProtectedRoutes)

app.MapPost("/chat", async (ChatRequest req, IHttpClientFactory factory) =>
{
    try
    {
        var response = await factory.CreateClient("openai").PostAsJsonAsync("v1/chat/completions", /* ... */);
        // ...
    }
    catch (LlmGuardBlockedException ex)               // a message (e.g. history) was blocked on the way out
    {
        return Results.Json(new { error = "prompt_blocked", message_index = ex.MessageIndex }, statusCode: 403);
    }
    catch (LlmGuardUnavailableException)              // FailClosed and the gateway gave no verdict
    {
        return Results.StatusCode(503);
    }
});
```

A complete version is in [`samples/ChatApi`](samples/ChatApi). Without an `Llm:BaseUrl` it uses a fake echo provider, so it runs with only the gateway:

```bash
LLMGUARD_API_KEY=<key> dotnet run --project samples/ChatApi
curl -X POST http://localhost:5080/chat -H "Content-Type: application/json" -d '{"prompt":"Hello"}'
```

### Options

| Setting | Default | Meaning |
|---|---|---|
| `GatewayUrl` | (required) | Base URL of the gateway |
| `ApiKey` | (required) | Sent as `X-API-Key`. Read from configuration, or from the `LLMGUARD_API_KEY` environment variable if configuration has none |
| `Timeout` | 2 s | Maximum time for one gateway check |
| `ProtectedRoutes` | none | Paths the middleware screens; each also covers its sub-paths. Only `POST`, `PUT` and `PATCH` are screened |
| `PromptJsonField` | `prompt` | JSON field holding the prompt; dots reach nested objects (`input.text`) |
| `FailMode` | `FailOpen` | What happens when the gateway gives no verdict (see below) |
| `MaxBodyBytes` | 1 MiB | Bodies larger than this on protected routes are rejected with 413 |

Invalid settings (missing key, non-HTTP URL, zero timeout) stop the app at startup rather than at the first request.

### Responses

| Situation | Middleware | Handler |
|---|---|---|
| Allowed | Request continues; body still readable | Request is sent |
| Blocked | **403** `{"error":"prompt_blocked","reason":"…","layer":"classifier"}` | Throws `LlmGuardBlockedException` (with `MessageIndex`, `Role`, `Decision`) |
| No verdict, `FailOpen` | Request continues; warning logged | Request is sent; warning logged |
| No verdict, `FailClosed` | **503** `{"error":"guard_unavailable",…}` | Throws `LlmGuardUnavailableException` |
| Body over `MaxBodyBytes` | **413** | n/a |
| No prompt field, not JSON, empty | Passes through unscreened (debug log) | Passes through unscreened |

"No verdict" covers a timeout, a connection error, any non-2xx reply (including 401 for a bad key) and a malformed reply (invalid JSON, unknown verdict, missing or out-of-range score). A malformed reply is never treated as "allow" by accident; it goes through `FailMode` like any other failure.

## Design decisions

**Fail-open is the default.** The gateway is a separate service, and with fail-closed any outage, deploy or slow response takes your whole chat feature down with it. Fail-open keeps the app available and logs a warning for every unscreened prompt, so the gap is visible and can be alerted on. Choose `FailClosed` when an unscreened prompt is worse than downtime, e.g. when the LLM has tools that act on real systems or access to sensitive data. Fail-closed returns 503 rather than 403 so clients and dashboards can tell "security check unavailable" apart from "prompt rejected".

**Prompts are never logged.** Prompts often contain personal data, credentials and confidential documents, and logs are copied to more places, kept longer and read by more people than the data they describe. Each check logs only the verdict, layer, score, latencies, source, prompt length and SHA-256 of the prompt. That is enough to count blocks, spot repeated attack payloads (same hash) and correlate with the gateway's own log, which records the same hash, without storing the text. Gateway response bodies are not logged either. Tests assert that a distinctive prompt never appears in any log output.

**The 403 body has no score.** Returning the classifier's score would let an attacker tune a prompt against it one probe at a time. The response says that the prompt was blocked and by which layer, nothing more.

**Oversized bodies are rejected, not skipped.** Passing a too-large body through unscreened would let an attacker bypass the check by padding the request.

**The handler checks every message, concurrently.** Injected instructions often arrive in conversation history, pasted documents or tool results rather than in the newest message. Each message is a separate gateway call, so one long message doesn't hide another, and the calls run in parallel so latency is about one check, not N. Messages with role `tool` or `function` are sent with `source: "rag"`.

**Handler failures are exceptions.** A synthetic 403 from a `DelegatingHandler` would look like the LLM provider refused the request. A typed exception makes the cause explicit and forces the calling code to decide what the user sees.

## Overhead

Measured with [`benchmarks/LlmGuard.Overhead`](benchmarks/LlmGuard.Overhead):
- **Setup:** 300 requests (after 20 warm-up) against the real gateway in its default `local_only` mode on the same laptop (i5-12500H, Windows 11, Release build).
- **Prompts:** the 200 deepset benchmark prompts plus 100 from the held-out test split. 80 were blocked.
- **Method:** the app runs in memory, and each request to a guarded route is paired with an identical request to an unguarded route.

| Per request | Mean | p50 | p95 |
|---|---|---|---|
| **Added by the middleware, total** | 95.5 ms | 65.0 ms | 297.5 ms |
| of which: gateway processing (classifier, rules) | 90.1 ms | 59.4 ms | 292.2 ms |
| of which: transport to the gateway (HTTP, JSON, uvicorn) | 5.2 ms | 5.1 ms | 6.2 ms |
| **of which: the middleware itself** (buffering, JSON parsing, hashing, logging) | **0.19 ms** | 0.15 ms | 0.41 ms |

A second run gave the same split (0.20 ms mean and 0.41 ms p95 for the middleware itself). Nearly all of the cost is the gateway's classifier, which runs on CPU and scales with prompt length.

```bash
GATEWAY_API_KEYS=<key> uvicorn app.main:app --port 8000          # repo root
LLMGUARD_API_KEY=<key> dotnet run -c Release --project benchmarks/LlmGuard.Overhead -- http://127.0.0.1:8000 300
```

## Development

```bash
cd dotnet
dotnet build LlmGuard.sln
dotnet test LlmGuard.sln                    # 60 tests, no gateway needed
dotnet pack src/LlmGuard -c Release -o artifacts
```

The tests use a fake gateway (a custom `HttpMessageHandler`) and need no network:
- **Client:** allow, block, timeouts and connection errors under each `FailMode`, ten kinds of malformed reply, HTTP errors, caller cancellation, and log privacy.
- **Handler:** multi-message and content-part payloads, tool messages screened as `rag`, pass-through cases, and concurrency.
- **Middleware:** tested on a minimal test host.
- **Sample:** tested end to end with `WebApplicationFactory`.

The projects target `net8.0` with C# 12 pinned in `Directory.Build.props`, so they build with the .NET 8 SDK (as CI does) or a newer one. CI (`.github/workflows/dotnet.yml`) builds and tests with the .NET 8 SDK on every push.

## Limitations

- The middleware screens one JSON string field. Prompts in form posts, query strings, multipart bodies or several fields aren't screened, so protect routes whose prompt lives in a known JSON field, or use the handler.
- The handler re-screens the full conversation on every turn, so long histories cost one gateway call per message per request. Calls are concurrent, but they still count against the gateway's capacity. Caching allowed verdicts by hash would avoid repeat checks.
- Using both the middleware and the handler, as the sample does, screens the newest prompt twice. That's intentional defense in depth, but it doubles the cost for that message.
- Detection quality is the gateway's: see the main README for what the classifier catches and misses (notably non-English attacks).
