using Sav.Application.Analyze;
using Sav.Domain.Attestations;
using Sav.Domain.Decisions;
using Sav.Domain.Policies;
using Sav.Infrastructure.Postgres.Redaction;

namespace Sav.Security.Tests.NoLeak;

public sealed class AnalyzeSqlResponseObjectNamesRedactionTests
{
    [Fact]
    public void RedactObject_strips_table_and_column_names_when_include_object_names_false()
    {
        DisclosureProfile profile = DisclosureProfileMerge.StrictDefaults();
        Assert.False(profile.IncludeObjectNames);

        StructuralSqlIr ir = new(
            dialect: "postgresql",
            statementTypes: ["Select"],
            tablesRead: ["secret_users", "orders"],
            tablesWritten: ["audit_log"],
            columnsRead: ["email", "ssn"],
            columnsWritten: ["payload"],
            functions: ["now"],
            hasMultipleStatements: false,
            hasDynamicSql: false,
            unresolvedObjects: ["missing_table"],
            riskCodes: ["ok"]);

        AnalyzeSqlResponse response = new(
            Decision: new PolicyDecision(
                PolicyOutcome.Allow,
                ["password=super-secret-password"],
                ["r1"]),
            Analysis: new AttestationAnalysis(ir, IsParsable: true),
            RedactedReasons: ["password=super-secret-password"],
            EffectiveDisclosure: profile);

        StrictRedactor redactor = new();
        AnalyzeSqlResponse redacted = redactor.RedactObject(response, profile);

        Assert.All(redacted.Analysis.Ir.TablesRead, n => Assert.Equal(StrictRedactor.RedactedToken, n));
        Assert.All(redacted.Analysis.Ir.TablesWritten, n => Assert.Equal(StrictRedactor.RedactedToken, n));
        Assert.All(redacted.Analysis.Ir.ColumnsRead, n => Assert.Equal(StrictRedactor.RedactedToken, n));
        Assert.All(redacted.Analysis.Ir.ColumnsWritten, n => Assert.Equal(StrictRedactor.RedactedToken, n));
        Assert.All(redacted.Analysis.Ir.UnresolvedObjects, n => Assert.Equal(StrictRedactor.RedactedToken, n));
        Assert.DoesNotContain("secret_users", redacted.Analysis.Ir.TablesRead, StringComparer.Ordinal);
        Assert.DoesNotContain("email", redacted.Analysis.Ir.ColumnsRead, StringComparer.Ordinal);
        Assert.DoesNotContain("super-secret-password", string.Join('|', redacted.RedactedReasons), StringComparison.Ordinal);
        Assert.DoesNotContain("super-secret-password", string.Join('|', redacted.Decision.Reasons), StringComparison.Ordinal);
        Assert.Contains(StrictRedactor.RedactedToken, string.Join('|', redacted.RedactedReasons), StringComparison.Ordinal);

        // Source response must remain untouched.
        Assert.Equal("secret_users", response.Analysis.Ir.TablesRead[0]);
    }

    [Fact]
    public void RedactObject_keeps_names_when_include_object_names_true()
    {
        DisclosureProfile profile = new(
            "names",
            IncludePlanSummary: false,
            IncludeObjectNames: true,
            IncludeTimings: false,
            IncludeRowCounts: false);

        StructuralSqlIr ir = new(
            dialect: "postgresql",
            statementTypes: ["Select"],
            tablesRead: ["public_users"],
            tablesWritten: [],
            columnsRead: ["id"],
            columnsWritten: [],
            functions: [],
            hasMultipleStatements: false,
            hasDynamicSql: false,
            unresolvedObjects: [],
            riskCodes: []);

        AnalyzeSqlResponse response = new(
            Decision: new PolicyDecision(PolicyOutcome.Allow, [], []),
            Analysis: new AttestationAnalysis(ir, IsParsable: true),
            RedactedReasons: [],
            EffectiveDisclosure: profile);

        AnalyzeSqlResponse redacted = new StrictRedactor().RedactObject(response, profile);

        Assert.Equal(["public_users"], redacted.Analysis.Ir.TablesRead);
        Assert.Equal(["id"], redacted.Analysis.Ir.ColumnsRead);
    }
}
