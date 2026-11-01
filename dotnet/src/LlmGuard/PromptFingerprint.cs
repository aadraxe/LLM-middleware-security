using System.Security.Cryptography;
using System.Text;

namespace LlmGuard;

/// <summary>Identifies a prompt in logs without revealing it.</summary>
internal static class PromptFingerprint
{
    /// <summary>Lower-case hex SHA-256 of the UTF-8 text.</summary>
    public static string Sha256(string text) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text))).ToLowerInvariant();
}
