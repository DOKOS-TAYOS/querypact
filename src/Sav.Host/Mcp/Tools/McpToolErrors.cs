using Sav.Application.Abstractions;
using Sav.Domain.Errors;
using Sav.Domain.Policies;
using Sav.Domain.Serialization;
using Sav.Host.Redaction;

namespace Sav.Host.Mcp.Tools;

/// <summary>
/// Shared MCP tool error envelope: typed JSON, redacted message, never stack traces.
/// </summary>
internal static class McpToolErrors
{
    public const string InternalError = "internal_error";

    private static readonly IRedactor Redactor = HostErrorRedactor.Create();
    private static readonly DisclosureProfile Strict = DisclosureProfileMerge.StrictDefaults();

    public static string FromSavException(SavException ex) =>
        CanonicalJson.Serialize(new { error = ex.Code, message = Redactor.RedactText(ex.Message, Strict) });

    public static string FromUnexpected(Exception ex)
    {
        _ = ex;
        return CanonicalJson.Serialize(new
        {
            error = InternalError,
            message = "An unexpected error occurred.",
        });
    }
}
