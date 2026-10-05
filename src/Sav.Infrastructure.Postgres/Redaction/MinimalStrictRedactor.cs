using System.Text.RegularExpressions;
using Sav.Application.Abstractions;
using Sav.Application.Analyze;
using Sav.Application.Migrations;
using Sav.Application.Verify;
using Sav.Domain.Attestations;
using Sav.Domain.Errors;
using Sav.Domain.Policies;
using Sav.Domain.Properties;

namespace Sav.Infrastructure.Postgres.Redaction;

/// <summary>
/// Older strict redactor still used on some PostgreSQL paths.
/// Prefer <see cref="StrictRedactor"/> + <see cref="PostgresErrorRedactor"/> for Host DI
/// (attestations / verify responses). Structured egress DTOs fail closed without that stack.
/// </summary>
public sealed partial class MinimalStrictRedactor : IRedactor
{
    public const string RedactedToken = "[REDACTED]";

    private static readonly string[] CanaryLiterals =
    [
        "CANARY_LITERAL_do_not_egress@example.invalid",
        "sav-ro-canary",
        "super-secret-password",
    ];

    public string RedactText(string value, DisclosureProfile profile)
    {
        ArgumentNullException.ThrowIfNull(profile);
        if (string.IsNullOrEmpty(value))
        {
            return value;
        }

        string result = value;
        result = UriPattern().Replace(result, RedactedToken);
        result = PasswordPattern().Replace(result, "$1" + RedactedToken);
        result = HostEqualsPattern().Replace(result, RedactedToken);
        result = PgPayloadPattern().Replace(result, "$1" + RedactedToken);
        result = StackTracePattern().Replace(result, RedactedToken);

        foreach (string canary in CanaryLiterals)
        {
            result = result.Replace(canary, RedactedToken, StringComparison.OrdinalIgnoreCase);
        }

        return result;
    }

    public T RedactObject<T>(T value, DisclosureProfile profile)
    {
        ArgumentNullException.ThrowIfNull(profile);
        if (value is null)
        {
            return value;
        }

        if (value is string text)
        {
            return (T)(object)RedactText(text, profile);
        }

        if (value is Exception ex)
        {
            string redactedMessage = RedactText(ex.Message, profile);
            if (ex is SavException sav)
            {
                return (T)(object)new SavException(sav.Code, redactedMessage);
            }

            return (T)(object)new Exception(redactedMessage);
        }

        if (IsStructuredEgressDto(value))
        {
            throw new InvalidOperationException(
                "MinimalStrictRedactor refuses structured egress type '"
                + typeof(T).FullName
                + "'; use StrictRedactor for attestations and verify/analyze responses.");
        }

        return value;
    }

    private static bool IsStructuredEgressDto(object value) =>
        value is Attestation
            or AnalyzeSqlResponse
            or VerifyQueryResponse
            or VerifyEquivalenceResponse
            or VerifyMigrationResponse
            or VerificationPipelineResult
            or PropertyResult
            or IReadOnlyList<PropertyResult>
            or AttestationAnalysis;


    [GeneratedRegex(@"postgres(?:ql)?://[^\s""']+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex UriPattern();

    [GeneratedRegex(@"(password\s*=\s*)([^\s;""']+)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex PasswordPattern();

    [GeneratedRegex(@"Host\s*=\s*[^\s;""']+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex HostEqualsPattern();

    [GeneratedRegex(@"\b(DETAIL|HINT|CONTEXT|NOTICE)\s*:\s*.+$", RegexOptions.IgnoreCase | RegexOptions.Multiline | RegexOptions.CultureInvariant)]
    private static partial Regex PgPayloadPattern();

    [GeneratedRegex(@"^\s*at\s+.+$", RegexOptions.Multiline | RegexOptions.CultureInvariant)]
    private static partial Regex StackTracePattern();
}
