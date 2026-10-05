using Sav.Domain.Errors;
using Sav.Infrastructure.Postgres.Oracle;

namespace Sav.Security.Tests.Bypass;

public sealed class QuerySucceedsTemplateBypassTests
{
    [Fact]
    public void Query_succeeds_template_always_wraps_agent_sql()
    {
        const string agent = "SELECT id FROM plan_items";
        var ir = OracleTestIr.Create(
            columnsRead: ["id"],
            tablesRead: ["plan_items"],
            agentSql: agent);

        string wrapped = OracleSqlBoundary.BuildWrappedCommand(
            OracleSqlTemplateKind.QuerySucceedsExists,
            ir,
            agent,
            policyAllowedFunctions: []);

        Assert.NotEqual(agent, wrapped);
        Assert.Equal(
            "SELECT COUNT(q)::bigint AS v FROM ( " + agent + " ) AS q",
            wrapped);
    }

    [Fact]
    public void Empty_result_template_always_wraps_agent_sql()
    {
        const string agent = "SELECT id FROM plan_items";
        var ir = OracleTestIr.Create(
            columnsRead: ["id"],
            tablesRead: ["plan_items"],
            agentSql: agent);

        string wrapped = OracleSqlBoundary.BuildWrappedCommand(
            OracleSqlTemplateKind.EmptyResultNotExists,
            ir,
            agent,
            policyAllowedFunctions: []);

        Assert.Equal(
            "SELECT NOT EXISTS (SELECT 1 FROM ( " + agent + " ) AS q) AS v",
            wrapped);
    }

    [Fact]
    public void Multi_statement_rejected_before_query_succeeds_wrap()
    {
        SavException ex = Assert.Throws<SavException>(
            () => OracleSqlBoundary.BuildWrappedCommand(
                OracleSqlTemplateKind.QuerySucceedsExists,
                OracleTestIr.Create(hasMultipleStatements: true, statementTypes: ["Select", "Select"]),
                "SELECT 1; SELECT 2",
                policyAllowedFunctions: []));

        Assert.Equal(SavErrorCode.UnsupportedConstruct, ex.Code);
    }
}
