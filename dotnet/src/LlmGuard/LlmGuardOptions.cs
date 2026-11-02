namespace LlmGuard;

/// <summary>What to do when the gateway can't give a verdict (down, slow, or a malformed reply).</summary>
public enum FailMode
{
    /// <summary>Explicit legacy opt-in: permit unscreened content and log a warning.</summary>
    FailOpen,

    /// <summary>Reject the prompt. Use when an unscreened prompt is worse than an outage.</summary>
    FailClosed,
}

/// <summary>
/// Settings for LlmGuard, bound from the <c>LlmGuard</c> configuration section.
/// The API key is read from configuration (e.g. the <c>LlmGuard__ApiKey</c> environment
/// variable or user secrets) or from the <c>LLMGUARD_API_KEY</c> environment variable.
/// </summary>
public sealed class LlmGuardOptions
{
    /// <summary>Configuration section the options are bound from.</summary>
    public const string SectionName = "LlmGuard";

    /// <summary>Environment variable used for the API key when configuration has none.</summary>
    public const string ApiKeyEnvironmentVariable = "LLMGUARD_API_KEY";

    /// <summary>Base URL of the security gateway, e.g. <c>http://localhost:8000</c>.</summary>
    public Uri? GatewayUrl { get; set; }

    /// <summary>Sent as <c>X-API-Key</c>. Never put this in source code or appsettings.json.</summary>
    public string? ApiKey { get; set; }

    /// <summary>Maximum time to wait for one gateway check. Default 2 seconds.</summary>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(2);

    /// <summary>Request paths the middleware screens (a path also covers its sub-paths), e.g. <c>/chat</c>.</summary>
    public List<string> ProtectedRoutes { get; set; } = new();

    /// <summary>JSON field holding the prompt in protected requests. Dots address nested
    /// objects, e.g. <c>input.text</c>. Default <c>prompt</c>.</summary>
    public string PromptJsonField { get; set; } = "prompt";

    /// <summary>Behaviour when screening is unavailable. Default <see cref="FailMode.FailClosed"/>.</summary>
    public FailMode FailMode { get; set; } = FailMode.FailClosed;

    /// <summary>Largest incoming or outgoing protected body to buffer. Oversized bodies
    /// are always rejected, including under FailOpen. Default 1 MiB.</summary>
    public int MaxBodyBytes { get; set; } = 1024 * 1024;
}
