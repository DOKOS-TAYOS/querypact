using Sav.Domain.Errors;
using Sav.Infrastructure.Postgres.Oracle;

namespace Sav.Security.Tests.Bypass;

public sealed class QueryEquivalentTemplateBypassTests
{
    [Fact]
    public void Except_all_templates_wrap_both_directions_as_count_only()
    {
        const string left = "SELECT id FROM t";
        const string right = "SELECT id FROM u";

        string leftWrap = OracleSqlTemplate.WrapExceptAll(
            OracleSqlTemplateKind.QueryEquivalentExceptLeft,
            left,
            right);
        string rightWrap = OracleSqlTemplate.WrapExceptAll(
            OracleSqlTemplateKind.QueryEquivalentExceptRight,
            left,
            right);

        Assert.Equal(
            "SELECT COUNT(*)::bigint AS v FROM ( ( " + left + " ) EXCEPT ALL ( " + right + " ) ) AS diff",
            leftWrap);
        Assert.Equal(
            "SELECT COUNT(*)::bigint AS v FROM ( ( " + right + " ) EXCEPT ALL ( " + left + " ) ) AS diff",
            rightWrap);
        Assert.StartsWith("SELECT COUNT(*)::bigint AS v FROM", leftWrap, StringComparison.Ordinal);
        Assert.DoesNotContain("SELECT *", leftWrap, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Equivalence_pair_rejects_multi_statement_left()
    {
        SavException ex = Assert.Throws<SavException>(
            () => OracleSqlBoundary.EnsureEquivalentSelectPairSafe(
                OracleTestIr.Create(hasMultipleStatements: true, statementTypes: ["Select", "Select"]),
                OracleTestIr.Create(agentSql: "SELECT 1"),
                "SELECT 1; SELECT 2",
                "SELECT 1",
                policyAllowedFunctions: []));

        Assert.Equal(SavErrorCode.UnsupportedConstruct, ex.Code);
    }

    [Fact]
    public void Equivalence_pair_rejects_dml_markers_in_right()
    {
        SavException ex = Assert.Throws<SavException>(
            () => OracleSqlBoundary.EnsureEquivalentSelectPairSafe(
                OracleTestIr.Create(agentSql: "SELECT 1"),
                OracleTestIr.Create(agentSql: "SELECT 1 FROM t; DELETE FROM t"),
                "SELECT 1",
                "SELECT 1 FROM t; DELETE FROM t",
                policyAllowedFunctions: []));

        Assert.Equal(SavErrorCode.UnsupportedConstruct, ex.Code);
    }

    [Fact]
    public void Equivalence_pair_rejects_write_ir()
    {
        SavException ex = Assert.Throws<SavException>(
            () => OracleSqlBoundary.EnsureEquivalentSelectPairSafe(
                OracleTestIr.Create(agentSql: "SELECT 1"),
                OracleTestIr.Create(
                    statementTypes: ["Insert"],
                    tablesWritten: ["t"],
                    agentSql: "INSERT INTO t VALUES (1)"),
                "SELECT 1",
                "SELECT 1",
                policyAllowedFunctions: []));

        Assert.Equal(SavErrorCode.UnsupportedConstruct, ex.Code);
    }
}
