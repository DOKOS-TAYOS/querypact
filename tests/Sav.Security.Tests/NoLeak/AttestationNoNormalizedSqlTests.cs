using Sav.Application.Abstractions;
using Sav.Application.Attestations;
using Sav.Domain.Attestations;
using Sav.Domain.Decisions;
using Sav.Domain.Plans;
using Sav.Domain.Policies;
using Sav.Domain.Properties;
using Sav.Domain.Serialization;
using Sav.Infrastructure.Postgres.Redaction;
using Sav.Infrastructure.Storage.Attestations;

namespace Sav.Security.Tests.NoLeak;

public sealed class AttestationNoNormalizedSqlTests
{
    private const string Canary = "CANARY_LITERAL_do_not_egress@example.invalid";
    private static readonly byte[] Key = Enumerable.Repeat((byte)0x11, 32).ToArray();

    [Fact]
    public void Factory_output_and_canonical_body_never_contain_normalized_sql_or_canary()
    {
        IRedactor redactor = new PostgresErrorRedactor(new StrictRedactor());
        AttestationFactory factory = new(new AttestationHmac(), redactor);

        string agentSql = "SELECT '" + Canary + "' AS secret FROM public.leak_table";
        AttestationDraft draft = new(
            SchemaVersion: "1",
            Id: "no-norm-1",
            SqlHash: AttestationMacMaterial.ComputeSqlHash(agentSql),
            ContractHash: AttestationMacMaterial.ComputeContractHash(new { id = "c" }),
            PolicyHash: AttestationMacMaterial.ComputePolicyHash(new { id = "p" }),
            SavVersion: "0.0.0-test",
            TargetAliasFingerprint: "fp",
            Decision: AttestationDecision.Deny,
            Analysis: new AttestationAnalysis(
                new StructuralSqlIr(
                    dialect: "postgresql",
                    statementTypes: ["SelectStmt"],
                    tablesRead: ["public.leak_table"],
                    tablesWritten: [],
                    columnsRead: [],
                    columnsWritten: [],
                    functions: [],
                    hasMultipleStatements: false,
                    hasDynamicSql: false,
                    unresolvedObjects: [],
                    riskCodes: []),
                IsParsable: true),
            PlanSummary: new PlanSummary("lt10", ["Seq Scan"], []),
            Properties:
            [
                new PropertyResult("query_succeeds", PropertyStatus.Fail, "DETAIL: " + Canary),
            ],
            EffectiveDisclosure: DisclosureProfileMerge.StrictDefaults(),
            Timestamp: DateTimeOffset.Parse("2026-07-25T12:00:00Z"));

        Attestation attestation = factory.Create(draft, Key);
        string bodyJson = CanonicalJson.Serialize(AttestationMacMaterial.ToCanonicalBody(attestation));
        string fullJson = CanonicalJson.Serialize(attestation);

        Assert.DoesNotContain("normalizedSql", bodyJson, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("NormalizedSql", fullJson, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(Canary, bodyJson, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(Canary, fullJson, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(agentSql, bodyJson, StringComparison.Ordinal);
        Assert.DoesNotContain("public.leak_table", bodyJson, StringComparison.Ordinal);
    }
}
