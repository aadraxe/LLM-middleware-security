using Microsoft.Extensions.Logging;

namespace LlmGuard;

/// <summary>
/// All LlmGuard log messages. Prompts are identified only by length and SHA-256;
/// prompt text and gateway response bodies are never logged.
/// </summary>
internal static partial class Log
{
    [LoggerMessage(EventId = 1, Level = LogLevel.Information,
        Message = "LlmGuard {Outcome}: layer={Layer} score={Score} gateway_ms={GatewayLatencyMs} elapsed_ms={ElapsedMs} source={Source} prompt_length={PromptLength} prompt_sha256={PromptSha256}")]
    public static partial void Checked(ILogger logger, GuardOutcome outcome, string? layer, double? score,
        double? gatewayLatencyMs, double elapsedMs, string source, int promptLength, string promptSha256);

    [LoggerMessage(EventId = 2, Level = LogLevel.Warning,
        Message = "LlmGuard {Outcome}: no verdict ({Reason}) elapsed_ms={ElapsedMs} source={Source} prompt_length={PromptLength} prompt_sha256={PromptSha256}")]
    public static partial void NoVerdict(ILogger logger, GuardOutcome outcome, string reason, double elapsedMs,
        string source, int promptLength, string promptSha256);

    [LoggerMessage(EventId = 3, Level = LogLevel.Debug,
        Message = "LlmGuard skipped {Path}: {Reason}")]
    public static partial void Skipped(ILogger logger, string path, string reason);

    [LoggerMessage(EventId = 4, Level = LogLevel.Warning,
        Message = "LlmGuard rejected {Path} with {StatusCode}: {Reason}")]
    public static partial void Rejected(ILogger logger, string path, int statusCode, string reason);
}
