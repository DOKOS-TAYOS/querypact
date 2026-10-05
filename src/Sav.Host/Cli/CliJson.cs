using System.Text.Json;
using Sav.Application.Abstractions;
using Sav.Domain.Errors;
using Sav.Domain.Policies;
using Sav.Domain.Serialization;
using Sav.Host.Redaction;

namespace Sav.Host.Cli;

/// <summary>
/// Shared CLI JSON egress helpers (responses already redacted by use cases).
/// </summary>
internal static class CliJson
{
    private static readonly IRedactor Redactor = HostErrorRedactor.Create();
    private static readonly DisclosureProfile Strict = DisclosureProfileMerge.StrictDefaults();

    public static void WriteSuccess<T>(TextWriter output, T value)
    {
        output.WriteLine(CanonicalJson.Serialize(value));
    }

    public static void WriteError(TextWriter error, string code, string message)
    {
        var payload = new { error = code, message };
        error.WriteLine(JsonSerializer.Serialize(payload));
    }

    public static void WriteSavException(TextWriter error, SavException ex)
    {
        WriteError(error, ex.Code, Redactor.RedactText(ex.Message, Strict));
    }
}
