using Sav.Application.Verify;
using Sav.Domain.Attestations;
using Sav.Domain.Decisions;
using Sav.Domain.Policies;
using Sav.Domain.Properties;
using Sav.Infrastructure.Postgres.Redaction;

namespace Sav.Security.Tests.NoLeak;

public sealed class VerifyEquivalenceResponseRedactionTests
{
    private const string Canary = "CANARY_LITERAL_do_not_egress@example.invalid";
    private const string SecretTable = "secret_users_canary_table";

    [Fact]
    public void RedactObject_VerifyEquivalenceResponse_redacts_nested_attestation()
    {
        DisclosureProfile profile = DisclosureProfileMerge.StrictDefaults();
        Assert.False(profile.IncludeObjectNames);

        StructuralSqlIr ir = new(
            dialect: "postgresql",
            statementTypes: ["Select"],
            tablesRead: [SecretTable],
            tablesWritten: [],
            columnsRead: ["email"],
            columnsWritten: [],
            functions: [],
            hasMultipleStatements: false,
            hasDynamicSql: false,
            unresolvedObjects: [],
            riskCodes: []);

        Attestation attestation = new(
            schemaVersion: "1",
            id: Guid.NewGuid().ToString("D"),
            sqlHash: "sql",
            contractHash: "contract",
            policyHash: "policy",
            savVersion: "0.0.0",
            targetAliasFingerprint: "fp",
            decision: AttestationDecision.Deny,
            analysis: new AttestationAnalysis(ir, IsParsable: true),
            planSummary: null,
            properties: [new PropertyResult("query_equivalent", PropertyStatus.Fail, Canary)],
            effectiveDisclosure: profile,
            timestamp: DateTimeOffset.UtcNow,
            hmacSha256Base64: "hmac");

        VerifyEquivalenceResponse response = new(attestation.Id, attestation);
        StrictRedactor redactor = new();

        VerifyEquivalenceResponse redacted = redactor.RedactObject(response, profile);

        Assert.All(redacted.Attestation.Analysis.Ir.TablesRead, n => Assert.Equal(StrictRedactor.RedactedToken, n));
        Assert.DoesNotContain(SecretTable, redacted.Attestation.Analysis.Ir.TablesRead, StringComparer.Ordinal);
        Assert.DoesNotContain(
            Canary,
            redacted.Attestation.Properties[0].RedactedDetail ?? string.Empty,
            StringComparison.OrdinalIgnoreCase);

        // Source must remain untouched (proves deep copy via typed branch, not no-op return).
        Assert.Equal(SecretTable, response.Attestation.Analysis.Ir.TablesRead[0]);
    }
}
