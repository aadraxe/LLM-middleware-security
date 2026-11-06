using System.Text.Json;

namespace LlmGuard;

// Internal outcomes are fixed codes, never attacker-controlled excerpts.
internal enum InspectionOutcome
{
    Inspected, UnsupportedFormat, MissingContent, InvalidJson,
    UnexpectedContentType, OversizedPayload, ExtractionFailure,
}

internal static class PayloadInspection
{
    internal static bool IsJson(string? contentType, string? charset = null) =>
        contentType is not null
        && (contentType.Equals("application/json", StringComparison.OrdinalIgnoreCase)
            || contentType.EndsWith("+json", StringComparison.OrdinalIgnoreCase))
        && (charset is null || charset.Trim('"').Equals("utf-8", StringComparison.OrdinalIgnoreCase));

    internal static bool HasDuplicateProperties(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            // Also reject case variants: downstream .NET bindings may ignore case.
            var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var property in element.EnumerateObject())
                if (!names.Add(property.Name) || HasDuplicateProperties(property.Value)) return true;
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in element.EnumerateArray())
                if (HasDuplicateProperties(item)) return true;
        }
        return false;
    }

    // At most limit+1 bytes are read; the caller distinguishes oversize without
    // buffering an arbitrarily large stream. Caller owns the input stream.
    internal static async Task<byte[]> ReadAsync(Stream stream, int limit, CancellationToken ct)
    {
        using var buffer = new MemoryStream();
        var chunk = new byte[8192];
        while (buffer.Length <= limit)
        {
            var count = (int)Math.Min(chunk.Length, (long)limit + 1 - buffer.Length);
            var read = await stream.ReadAsync(chunk.AsMemory(0, count), ct).ConfigureAwait(false);
            if (read == 0) break;
            await buffer.WriteAsync(chunk.AsMemory(0, read), ct).ConfigureAwait(false);
        }
        return buffer.ToArray();
    }
}
