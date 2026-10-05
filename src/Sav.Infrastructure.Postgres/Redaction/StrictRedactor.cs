using System.Globalization;
using System.Text.RegularExpressions;
using Sav.Application.Abstractions;
using Sav.Application.Analyze;
using Sav.Application.Migrations;
using Sav.Application.Verify;
using Sav.Domain.Attestations;
using Sav.Domain.Decisions;
using Sav.Domain.Errors;
using Sav.Domain.Plans;
using Sav.Domain.Policies;
using Sav.Domain.Properties;

namespace Sav.Infrastructure.Postgres.Redaction;

/// <summary>
/// DisclosureProfile-aware redactor used by Host DI. Always strips secrets; disclosure flags
/// control bucketed counts/timings/names/plan channels.
/// </summary>
public sealed partial class StrictRedactor : IRedactor
{
    public const string RedactedToken = MinimalStrictRedactor.RedactedToken;

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
        result = SqlLiteralPattern().Replace(result, "'[REDACTED]'");

        foreach (string canary in CanaryLiterals)
        {
            result = result.Replace(canary, RedactedToken, StringComparison.OrdinalIgnoreCase);
        }

        if (!profile.IncludePlanSummary)
        {
            result = ExplainLiteralPattern().Replace(result, RedactedToken);
        }

        if (!profile.IncludeObjectNames)
        {
            result = RelationNamePattern().Replace(result, "$1=" + RedactedToken);
        }

        result = RedactCounts(result, profile);
        result = RedactTimings(result, profile);

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

        if (value is PropertyResult property)
        {
            return (T)(object)RedactPropertyResult(property, profile);
        }

        if (value is PlanSummary plan)
        {
            return (T)(object)RedactPlanSummary(plan, profile);
        }

        if (value is IReadOnlyList<PropertyResult> properties)
        {
            PropertyResult[] copy = properties.Select(p => RedactPropertyResult(p, profile)).ToArray();
            return (T)(object)copy;
        }

        if (value is Attestation attestation)
        {
            return (T)(object)RedactAttestation(attestation, profile);
        }

        if (value is VerifyMigrationResponse migrationResponse)
        {
            Attestation redacted = RedactAttestation(migrationResponse.Attestation, profile);
            return (T)(object)new VerifyMigrationResponse(migrationResponse.AttestationId, redacted);
        }

        if (value is VerifyEquivalenceResponse equivalenceResponse)
        {
            Attestation redacted = RedactAttestation(equivalenceResponse.Attestation, profile);
            return (T)(object)new VerifyEquivalenceResponse(equivalenceResponse.AttestationId, redacted);
        }

        if (value is VerifyQueryResponse verifyQueryResponse)
        {
            Attestation redacted = RedactAttestation(verifyQueryResponse.Attestation, profile);
            return (T)(object)new VerifyQueryResponse(verifyQueryResponse.AttestationId, redacted);
        }

        if (value is VerificationPipelineResult pipelineResult)
        {
            return (T)(object)RedactVerificationPipelineResult(pipelineResult, profile);
        }

        if (value is AttestationAnalysis analysis)
        {
            return (T)(object)RedactAnalysis(analysis, profile);
        }

        if (value is AnalyzeSqlResponse analyzeResponse)
        {
            return (T)(object)RedactAnalyzeSqlResponse(analyzeResponse, profile);
        }

        return value;
    }

    private AnalyzeSqlResponse RedactAnalyzeSqlResponse(
        AnalyzeSqlResponse response,
        DisclosureProfile profile)
    {
        AttestationAnalysis analysis = RedactAnalysis(response.Analysis, profile);
        string[] redactedReasons = response.RedactedReasons
            .Select(r => RedactText(r, profile))
            .ToArray();
        string[] decisionReasons = response.Decision.Reasons
            .Select(r => RedactText(r, profile))
            .ToArray();
        PolicyDecision decision = new(
            response.Decision.Outcome,
            decisionReasons,
            response.Decision.RuleIds);

        return new AnalyzeSqlResponse(
            decision,
            analysis,
            redactedReasons,
            response.EffectiveDisclosure);
    }

    private VerificationPipelineResult RedactVerificationPipelineResult(
        VerificationPipelineResult result,
        DisclosureProfile profile)
    {
        PlanSummary? plan = result.PlanSummary is null
            ? null
            : RedactPlanSummary(result.PlanSummary, profile);
        PropertyResult[] props = result.Properties
            .Select(p => RedactPropertyResult(p, profile))
            .ToArray();
        AttestationAnalysis analysis = RedactAnalysis(result.Analysis, profile);
        string[] reasons = result.RedactedReasons
            .Select(r => RedactText(r, profile))
            .ToArray();

        return new VerificationPipelineResult(
            result.Decision,
            analysis,
            plan,
            props,
            result.EffectiveDisclosure,
            reasons);
    }

    private Attestation RedactAttestation(Attestation attestation, DisclosureProfile profile)
    {
        PlanSummary? plan = attestation.PlanSummary is null
            ? null
            : RedactPlanSummary(attestation.PlanSummary, profile);
        PropertyResult[] props = attestation.Properties
            .Select(p => RedactPropertyResult(p, profile))
            .ToArray();
        AttestationAnalysis analysis = RedactAnalysis(attestation.Analysis, profile);

        return new Attestation(
            schemaVersion: attestation.SchemaVersion,
            id: attestation.Id,
            sqlHash: attestation.SqlHash,
            contractHash: attestation.ContractHash,
            policyHash: attestation.PolicyHash,
            savVersion: attestation.SavVersion,
            targetAliasFingerprint: attestation.TargetAliasFingerprint,
            decision: attestation.Decision,
            analysis: analysis,
            planSummary: plan,
            properties: props,
            effectiveDisclosure: attestation.EffectiveDisclosure,
            timestamp: attestation.Timestamp,
            hmacSha256Base64: attestation.HmacSha256Base64);
    }

    private AttestationAnalysis RedactAnalysis(AttestationAnalysis analysis, DisclosureProfile profile)
    {
        StructuralSqlIr ir = analysis.Ir;
        if (profile.IncludeObjectNames)
        {
            return analysis;
        }

        StructuralSqlIr scrubbed = new(
            dialect: ir.Dialect,
            statementTypes: ir.StatementTypes,
            tablesRead: ScrubNames(ir.TablesRead),
            tablesWritten: ScrubNames(ir.TablesWritten),
            columnsRead: ScrubNames(ir.ColumnsRead),
            columnsWritten: ScrubNames(ir.ColumnsWritten),
            functions: ScrubNames(ir.Functions),
            hasMultipleStatements: ir.HasMultipleStatements,
            hasDynamicSql: ir.HasDynamicSql,
            unresolvedObjects: ScrubNames(ir.UnresolvedObjects),
            riskCodes: ir.RiskCodes);

        return new AttestationAnalysis(scrubbed, analysis.IsParsable);
    }

    private static string[] ScrubNames(IReadOnlyList<string> names) =>
        names.Select(static _ => RedactedToken).ToArray();

    /// <summary>Orders-of-magnitude bucket for allowed count disclosure (never exact cardinalities).</summary>
    public static string BucketCount(long count)
    {
        if (count < 0)
        {
            return "unknown";
        }

        if (count < 10)
        {
            return "lt10";
        }

        if (count < 100)
        {
            return "tens";
        }

        if (count < 1000)
        {
            return "hundreds";
        }

        if (count < 10_000)
        {
            return "thousands";
        }

        return "10k_plus";
    }

    /// <summary>Orders-of-magnitude bucket for allowed timing disclosure (never exact ms).</summary>
    public static string BucketTimingMs(double milliseconds)
    {
        if (milliseconds < 0)
        {
            return "unknown";
        }

        if (milliseconds < 10)
        {
            return "lt10ms";
        }

        if (milliseconds < 100)
        {
            return "tens_ms";
        }

        if (milliseconds < 1000)
        {
            return "hundreds_ms";
        }

        return "seconds_plus";
    }

    private PropertyResult RedactPropertyResult(PropertyResult property, DisclosureProfile profile)
    {
        string? detail = property.RedactedDetail;
        if (detail is null)
        {
            return property;
        }

        if (!profile.IncludeRowCounts)
        {
            if (FixedPropertyDetailCodes.Contains(detail))
            {
                return property;
            }

            // Strip drafts that smuggle exact v / COUNT before egress.
            string scrubbed = RedactText(detail, profile);
            if (FixedPropertyDetailCodes.Contains(scrubbed))
            {
                return new PropertyResult(property.Name, property.Status, scrubbed);
            }

            if (ContainsExactCountSignal(detail) || LooksLikeScalarV(detail))
            {
                if (property.Status == PropertyStatus.Pass)
                {
                    return new PropertyResult(property.Name, property.Status, null);
                }

                string code = property.Name switch
                {
                    "unique" => SavErrorCode.UniqueViolation,
                    "non_null" => SavErrorCode.NullFound,
                    "empty_result" => SavErrorCode.EmptyExpectedRows,
                    _ => SavErrorCode.QueryFailed,
                };
                return new PropertyResult(property.Name, property.Status, code);
            }

            // Unknown free text must never enter attestations under strict counts.
            return new PropertyResult(property.Name, property.Status, SavErrorCode.QueryFailed);
        }

        string withBuckets = ExactCountPattern().Replace(
            detail,
            m =>
            {
                if (!long.TryParse(m.Groups[1].Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out long n))
                {
                    return RedactedToken;
                }

                return "count=" + BucketCount(n);
            });
        return new PropertyResult(property.Name, property.Status, RedactText(withBuckets, profile));
    }

    private PlanSummary RedactPlanSummary(PlanSummary summary, DisclosureProfile profile)
    {
        if (!profile.IncludePlanSummary)
        {
            return new PlanSummary(summary.CostBucket, [], summary.RiskFlags);
        }

        IReadOnlyList<string> nodes = profile.IncludeObjectNames
            ? summary.NodeTypes
            : summary.NodeTypes.Select(n => RedactText(n, profile)).ToArray();

        return new PlanSummary(summary.CostBucket, nodes, summary.RiskFlags);
    }

    private static string RedactCounts(string value, DisclosureProfile profile)
    {
        if (!profile.IncludeRowCounts)
        {
            return ExactCountPattern().Replace(value, "count=" + RedactedToken);
        }

        return ExactCountPattern().Replace(
            value,
            m =>
            {
                if (!long.TryParse(m.Groups[1].Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out long n))
                {
                    return "count=" + RedactedToken;
                }

                return "count=" + BucketCount(n);
            });
    }

    private static string RedactTimings(string value, DisclosureProfile profile)
    {
        if (!profile.IncludeTimings)
        {
            return ExactTimingPattern().Replace(value, "time=" + RedactedToken);
        }

        return ExactTimingPattern().Replace(
            value,
            m =>
            {
                if (!double.TryParse(m.Groups[1].Value, NumberStyles.Float, CultureInfo.InvariantCulture, out double ms))
                {
                    return "time=" + RedactedToken;
                }

                return "time=" + BucketTimingMs(ms);
            });
    }

    private static bool ContainsExactCountSignal(string detail) =>
        ExactCountPattern().IsMatch(detail) || detail.Contains("rows=", StringComparison.OrdinalIgnoreCase);

    private static bool LooksLikeScalarV(string detail) =>
        ScalarVPattern().IsMatch(detail);

    [GeneratedRegex(@"postgres(?:ql)?://[^\s""']+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex UriPattern();

    [GeneratedRegex(@"(password\s*=\s*)([^\s;""']+)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex PasswordPattern();

    [GeneratedRegex(@"Host\s*=\s*[^\s;""']+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex HostEqualsPattern();

    [GeneratedRegex(@"\b(DETAIL|HINT|CONTEXT|NOTICE|RAISE)\s*:\s*.+$", RegexOptions.IgnoreCase | RegexOptions.Multiline | RegexOptions.CultureInvariant)]
    private static partial Regex PgPayloadPattern();

    [GeneratedRegex(@"^\s*at\s+.+$", RegexOptions.Multiline | RegexOptions.CultureInvariant)]
    private static partial Regex StackTracePattern();

    [GeneratedRegex(@"'(?:[^']|'')*'", RegexOptions.CultureInvariant)]
    private static partial Regex SqlLiteralPattern();

    [GeneratedRegex(@"\b(Filter|Output|Index Cond|Hash Cond|Merge Cond|Recheck Cond)\b[^\n]*", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex ExplainLiteralPattern();

    [GeneratedRegex(@"\b(Relation Name|Alias|table|relation)\s*[:=]\s*[^\s,;]+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex RelationNamePattern();

    [GeneratedRegex(@"\b(?:rows|count|plan rows|v)\s*[:=]\s*(\d+)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex ExactCountPattern();

    [GeneratedRegex(@"\b(?:time|duration|elapsed)\s*[:=]?\s*(\d+(?:\.\d+)?)\s*ms\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex ExactTimingPattern();

    [GeneratedRegex(@"^\s*v\s*=\s*\d+\s*$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex ScalarVPattern();
}
