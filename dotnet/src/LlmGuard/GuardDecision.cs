namespace LlmGuard;

/// <summary>How a check ended.</summary>
public enum GuardOutcome
{
    /// <summary>The gateway allowed the text.</summary>
    Allowed,
    /// <summary>The gateway blocked the text.</summary>
    Blocked,
    /// <summary>No verdict (gateway down, slow or malformed reply); allowed because of <see cref="FailMode.FailOpen"/>.</summary>
    FailedOpen,
    /// <summary>No verdict; rejected because of <see cref="FailMode.FailClosed"/>.</summary>
    FailedClosed,
}

/// <summary>The result of screening one piece of text.</summary>
/// <param name="Outcome">How the check ended.</param>
/// <param name="Score">Gateway risk score (0–1), when a verdict was obtained.</param>
/// <param name="Layer">Gateway stage that decided (rules, fuzzy, classifier, judge), when a verdict was obtained.</param>
/// <param name="GatewayLatencyMs">Processing time reported by the gateway.</param>
/// <param name="ElapsedMs">Total time this check took on the client side, including the HTTP round trip.</param>
/// <param name="FailureReason">Why no verdict was obtained, for the FailedOpen/FailedClosed outcomes.</param>
public sealed record GuardDecision(
    GuardOutcome Outcome,
    double? Score,
    string? Layer,
    double? GatewayLatencyMs,
    double ElapsedMs,
    string? FailureReason)
{
    /// <summary>True when the request may proceed.</summary>
    public bool IsAllowed => Outcome is GuardOutcome.Allowed or GuardOutcome.FailedOpen;
}

/// <summary>Base type for prompts LlmGuard refused to let through.</summary>
public abstract class LlmGuardException : Exception
{
    /// <summary>The decision that caused the refusal.</summary>
    public GuardDecision Decision { get; }

    /// <summary>Index of the offending message in the chat payload.</summary>
    public int MessageIndex { get; }

    /// <summary>Role of the offending message (user, system, assistant, tool), if present.</summary>
    public string? Role { get; }

    /// <summary>Creates the exception.</summary>
    protected LlmGuardException(string message, GuardDecision decision, int messageIndex, string? role)
        : base(message)
    {
        Decision = decision;
        MessageIndex = messageIndex;
        Role = role;
    }
}

/// <summary>Thrown by <see cref="LlmGuardHandler"/> when the gateway blocks a message; the request is not sent.</summary>
public sealed class LlmGuardBlockedException : LlmGuardException
{
    /// <summary>Creates the exception.</summary>
    public LlmGuardBlockedException(GuardDecision decision, int messageIndex, string? role)
        : base($"LlmGuard blocked message {messageIndex} (layer: {decision.Layer}).", decision, messageIndex, role) { }
}

/// <summary>Thrown when screening fails closed, including oversized or unreadable payloads in any failure mode.</summary>
public sealed class LlmGuardUnavailableException : LlmGuardException
{
    /// <summary>Creates the exception.</summary>
    public LlmGuardUnavailableException(GuardDecision decision, int messageIndex, string? role)
        : base($"LlmGuard could not screen message {messageIndex}: {decision.FailureReason}", decision, messageIndex, role) { }
}
