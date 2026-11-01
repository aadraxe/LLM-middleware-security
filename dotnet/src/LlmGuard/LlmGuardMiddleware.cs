using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace LlmGuard;

/// <summary>
/// Screens incoming requests on <see cref="LlmGuardOptions.ProtectedRoutes"/>: reads the
/// prompt from <see cref="LlmGuardOptions.PromptJsonField"/> in the JSON body and asks the
/// gateway. Blocked prompts get 403; under <see cref="FailMode.FailClosed"/>, prompts that
/// could not be screened get 503. Everything else continues down the pipeline with the
/// body intact.
/// </summary>
public sealed class LlmGuardMiddleware
{
    private static readonly string[] ScreenedMethods = { "POST", "PUT", "PATCH" };

    private readonly RequestDelegate _next;
    private readonly LlmGuardOptions _options;
    private readonly ILogger<LlmGuardMiddleware> _logger;
    private readonly PathString[] _routes;
    private readonly string[] _fieldPath;

    /// <summary>Created by <c>app.UseLlmGuard()</c>.</summary>
    public LlmGuardMiddleware(RequestDelegate next, IOptions<LlmGuardOptions> options, ILogger<LlmGuardMiddleware> logger)
    {
        _next = next;
        _options = options.Value;
        _logger = logger;
        _routes = _options.ProtectedRoutes.Select(r => new PathString(r.StartsWith('/') ? r : "/" + r)).ToArray();
        _fieldPath = _options.PromptJsonField.Split('.');
    }

    /// <summary>Processes one request.</summary>
    public async Task InvokeAsync(HttpContext context, ILlmGuardClient guard)
    {
        var request = context.Request;
        if (!IsProtected(request))
        {
            await _next(context);
            return;
        }

        if (request.ContentLength > _options.MaxBodyBytes)
        {
            await RejectAsync(context, StatusCodes.Status413PayloadTooLarge, "payload_too_large",
                "The request body is too large to screen.", null);
            return;
        }

        request.EnableBuffering(bufferThreshold: 64 * 1024, bufferLimit: _options.MaxBodyBytes + 1L);
        byte[] body;
        try
        {
            body = await ReadBodyAsync(request, context.RequestAborted);
        }
        catch (IOException)
        {
            // The buffer limit was exceeded (no Content-Length, chunked upload)
            await RejectAsync(context, StatusCodes.Status413PayloadTooLarge, "payload_too_large",
                "The request body is too large to screen.", null);
            return;
        }
        request.Body.Position = 0;
        if (body.Length > _options.MaxBodyBytes)
        {
            await RejectAsync(context, StatusCodes.Status413PayloadTooLarge, "payload_too_large",
                "The request body is too large to screen.", null);
            return;
        }

        var prompt = ExtractPrompt(body, out var skipReason);
        if (prompt is null)
        {
            Log.Skipped(_logger, request.Path, skipReason);
            await _next(context);
            return;
        }

        var decision = await guard.CheckAsync(prompt, "user", context.RequestAborted);
        if (decision.IsAllowed)
        {
            await _next(context);
            return;
        }

        if (decision.Outcome == GuardOutcome.Blocked)
        {
            await RejectAsync(context, StatusCodes.Status403Forbidden, "prompt_blocked",
                "The prompt was blocked by the LLM security gateway.", decision.Layer);
        }
        else
        {
            await RejectAsync(context, StatusCodes.Status503ServiceUnavailable, "guard_unavailable",
                "The prompt could not be screened because the LLM security gateway is unavailable.", null);
        }
    }

    private bool IsProtected(HttpRequest request) =>
        ScreenedMethods.Contains(request.Method, StringComparer.OrdinalIgnoreCase)
        && _routes.Any(route => request.Path.StartsWithSegments(route, StringComparison.OrdinalIgnoreCase));

    private async Task<byte[]> ReadBodyAsync(HttpRequest request, CancellationToken cancellationToken)
    {
        using var buffer = new MemoryStream();
        await request.Body.CopyToAsync(buffer, cancellationToken);
        return buffer.ToArray();
    }

    private string? ExtractPrompt(byte[] body, out string skipReason)
    {
        skipReason = "";
        if (body.Length == 0)
        {
            skipReason = "empty body";
            return null;
        }
        try
        {
            using var document = JsonDocument.Parse(body);
            var element = document.RootElement;
            foreach (var segment in _fieldPath)
            {
                if (element.ValueKind != JsonValueKind.Object || !element.TryGetProperty(segment, out element))
                {
                    skipReason = $"no '{_options.PromptJsonField}' field";
                    return null;
                }
            }
            if (element.ValueKind != JsonValueKind.String)
            {
                skipReason = $"'{_options.PromptJsonField}' is not a string";
                return null;
            }
            var prompt = element.GetString();
            if (string.IsNullOrEmpty(prompt))
            {
                skipReason = $"'{_options.PromptJsonField}' is empty";
                return null;
            }
            return prompt;
        }
        catch (JsonException)
        {
            skipReason = "body is not valid JSON";
            return null;
        }
    }

    private async Task RejectAsync(HttpContext context, int statusCode, string error, string reason, string? layer)
    {
        Log.Rejected(_logger, context.Request.Path, statusCode, error);
        context.Response.StatusCode = statusCode;
        // The score is deliberately not returned: it would let a caller tune an attack
        // against the classifier one probe at a time.
        await context.Response.WriteAsJsonAsync(new RejectionBody(error, reason, layer), context.RequestAborted);
    }

    private sealed record RejectionBody(string Error, string Reason, string? Layer);
}
