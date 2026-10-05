using Sav.Application.Abstractions;
using Sav.Domain.Analysis;
using Sav.Domain.Errors;
using Sav.Infrastructure.Postgres.Oracle;
using Sav.Infrastructure.Postgres.Parsing;

namespace Sav.Security.Tests.Bypass;

public sealed class OracleSqlBoundaryBypassTests
{
    [Fact]
    public void Rejects_multi_statement_agent_sql()
    {
        SqlIr ir = OracleTestIr.Create(
            statementTypes: ["Select", "Select"],
            hasMultipleStatements: true,
            agentSql: "SELECT 1; SELECT 2");

        SavException ex = Assert.Throws<SavException>(
            () => OracleSqlBoundary.BuildWrappedCommand(
                OracleSqlTemplateKind.QuerySucceedsExists,
                ir,
                "SELECT 1; SELECT 2",
                policyAllowedFunctions: []));

        Assert.Equal(SavErrorCode.UnsupportedConstruct, ex.Code);
    }

    [Fact]
    public void Rejects_pg_read_file_style_function()
    {
        SqlIr ir = OracleTestIr.Create(
            functions: ["pg_read_file"],
            agentSql: "SELECT pg_read_file('pg_hba.conf')");

        SavException ex = Assert.Throws<SavException>(
            () => OracleSqlBoundary.BuildWrappedCommand(
                OracleSqlTemplateKind.QuerySucceedsExists,
                ir,
                "SELECT pg_read_file('pg_hba.conf')",
                policyAllowedFunctions: []));

        Assert.Equal(SavErrorCode.UnsupportedConstruct, ex.Code);
    }

    [Fact]
    public void Rejects_write_verb_smuggled_in_cte()
    {
        const string sql = """
            WITH x AS (
              INSERT INTO side_effect_sink(v) VALUES ('x') RETURNING v
            )
            SELECT v FROM x
            """;
        SqlIr ir = OracleTestIr.Create(
            statementTypes: ["Select"],
            tablesWritten: ["side_effect_sink"],
            agentSql: sql);

        SavException ex = Assert.Throws<SavException>(
            () => OracleSqlBoundary.BuildWrappedCommand(
                OracleSqlTemplateKind.EmptyResultNotExists,
                ir,
                sql,
                policyAllowedFunctions: []));

        Assert.Equal(SavErrorCode.UnsupportedConstruct, ex.Code);
    }

    [Theory]
    [InlineData("WITH x AS (INSERT INTO t(v) VALUES ('x') RETURNING v) SELECT v FROM x")]
    [InlineData("WITH x AS (/**/INSERT INTO t(v) VALUES ('x') RETURNING v) SELECT v FROM x")]
    public void Real_parser_cte_modifying_statement_has_tables_written_and_boundary_rejects(string sql)
    {
        ISqlParser parser = new LibPgQuerySqlParser();
        SqlParseResult parsed = parser.Parse(sql, CancellationToken.None);

        Assert.True(parsed.Success);
        Assert.NotNull(parsed.Ir);
        Assert.NotEmpty(parsed.Ir.TablesWritten);

        SavException ex = Assert.Throws<SavException>(
            () => OracleSqlBoundary.BuildWrappedCommand(
                OracleSqlTemplateKind.QuerySucceedsExists,
                parsed.Ir,
                sql,
                policyAllowedFunctions: []));

        Assert.Equal(SavErrorCode.UnsupportedConstruct, ex.Code);
    }

    [Fact]
    public void Rejects_comment_smuggled_insert_marker_when_ir_misses_tables_written()
    {
        // Defense-in-depth: markers must catch /**/INSERT even if TablesWritten is empty (mapper miss).
        // Use UPDATE (no " into " token) so the textual "update" marker is the defense-in-depth check.
        const string sql = "WITH x AS (/**/UPDATE t SET v = 'x' RETURNING v) SELECT v FROM x";
        SqlIr ir = OracleTestIr.Create(
            statementTypes: ["Select"],
            tablesWritten: [],
            agentSql: sql);

        SavException ex = Assert.Throws<SavException>(
            () => OracleSqlBoundary.BuildWrappedCommand(
                OracleSqlTemplateKind.QuerySucceedsExists,
                ir,
                sql,
                policyAllowedFunctions: []));

        Assert.Equal(SavErrorCode.UnsupportedConstruct, ex.Code);
    }

    [Theory]
    [InlineData("SELECT 'drop table t; update t'")]
    [InlineData("SELECT 'insert into t values (1)' AS payload")]
    [InlineData("SELECT \u0024\u0024delete from t; truncate t\u0024\u0024")]
    [InlineData("SELECT 1 AS \" drop \"")]
    [InlineData("SELECT 1 -- delete from t;")]
    [InlineData("SELECT 1 /* drop t; /* nested */ update t */")]
    public void Allows_dangerous_words_inside_non_executable_lexical_segments(string sql)
    {
        ISqlParser parser = new LibPgQuerySqlParser();
        SqlParseResult parsed = parser.Parse(sql, CancellationToken.None);

        Assert.True(parsed.Success, parsed.RedactedMessage);
        Assert.NotNull(parsed.Ir);
        string wrapped = OracleSqlBoundary.BuildWrappedCommand(
            OracleSqlTemplateKind.QuerySucceedsExists,
            parsed.Ir,
            sql,
            policyAllowedFunctions: []);

        Assert.Contains(sql, wrapped, StringComparison.Ordinal);
    }

    [Fact]
    public void Rejects_write_marker_between_dollar_sign_identifier_fragments()
    {
        const string sql =
            "WITH foo$tag$ AS (UPDATE t SET v = 1 RETURNING v), "
            + "bar$tag$ AS (SELECT 1) SELECT 1";
        SqlIr ir = OracleTestIr.Create(
            statementTypes: ["Select"],
            tablesWritten: [],
            agentSql: sql);

        SavException ex = Assert.Throws<SavException>(
            () => OracleSqlBoundary.BuildWrappedCommand(
                OracleSqlTemplateKind.QuerySucceedsExists,
                ir,
                sql,
                policyAllowedFunctions: []));

        Assert.Equal(SavErrorCode.UnsupportedConstruct, ex.Code);
    }

    [Fact]
    public void Rejects_tab_separated_write_marker_when_ir_misses_tables_written()
    {
        const string sql = "WITH x AS (\tUPDATE\tt SET v = 'x' RETURNING v) SELECT v FROM x";
        SqlIr ir = OracleTestIr.Create(
            statementTypes: ["Select"],
            tablesWritten: [],
            agentSql: sql);

        SavException ex = Assert.Throws<SavException>(
            () => OracleSqlBoundary.BuildWrappedCommand(
                OracleSqlTemplateKind.QuerySucceedsExists,
                ir,
                sql,
                policyAllowedFunctions: []));

        Assert.Equal(SavErrorCode.UnsupportedConstruct, ex.Code);
    }

    [Fact]
    public void Rejects_executable_semicolon_even_when_ir_claims_single_statement()
    {
        const string sql = "SELECT 1; SELECT 2";
        SqlIr ir = OracleTestIr.Create(
            statementTypes: ["Select"],
            hasMultipleStatements: false,
            agentSql: sql);

        SavException ex = Assert.Throws<SavException>(
            () => OracleSqlBoundary.BuildWrappedCommand(
                OracleSqlTemplateKind.QuerySucceedsExists,
                ir,
                sql,
                policyAllowedFunctions: []));

        Assert.Equal(SavErrorCode.UnsupportedConstruct, ex.Code);
    }

    [Theory]
    [InlineData("SELECT 'unterminated")]
    [InlineData("SELECT \"unterminated")]
    [InlineData("SELECT /* unterminated")]
    [InlineData("SELECT \u0024tag\u0024unterminated")]
    public void Rejects_unterminated_masked_lexical_segments(string sql)
    {
        SqlIr ir = OracleTestIr.Create(agentSql: sql);

        SavException ex = Assert.Throws<SavException>(
            () => OracleSqlBoundary.BuildWrappedCommand(
                OracleSqlTemplateKind.QuerySucceedsExists,
                ir,
                sql,
                policyAllowedFunctions: []));

        Assert.Equal(SavErrorCode.UnsupportedConstruct, ex.Code);
    }

    [Fact]
    public void Never_returns_raw_agent_sql_as_command_text()
    {
        const string agent = "SELECT id, payload FROM plan_items";
        SqlIr ir = OracleTestIr.Create(
            columnsRead: ["id", "payload"],
            tablesRead: ["plan_items"],
            agentSql: agent);

        string wrapped = OracleSqlBoundary.BuildWrappedCommand(
            OracleSqlTemplateKind.QuerySucceedsExists,
            ir,
            agent,
            policyAllowedFunctions: []);

        Assert.NotEqual(agent, wrapped);
        Assert.StartsWith("SELECT COUNT(q)::bigint AS v FROM (", wrapped, StringComparison.Ordinal);
        Assert.EndsWith(") AS q", wrapped, StringComparison.Ordinal);
        Assert.Contains(agent, wrapped, StringComparison.Ordinal);
    }

    [Fact]
    public void Rejects_dynamic_sql_flag()
    {
        SqlIr ir = OracleTestIr.Create(hasDynamicSql: true, agentSql: "EXECUTE 'SELECT 1'");

        SavException ex = Assert.Throws<SavException>(
            () => OracleSqlBoundary.BuildWrappedCommand(
                OracleSqlTemplateKind.QuerySucceedsExists,
                ir,
                "EXECUTE 'SELECT 1'",
                policyAllowedFunctions: []));

        Assert.Equal(SavErrorCode.UnsupportedConstruct, ex.Code);
    }

    [Fact]
    public void Empty_policy_allowed_functions_denies_any_agent_function()
    {
        SqlIr ir = OracleTestIr.Create(
            functions: ["upper"],
            agentSql: "SELECT upper(payload) FROM plan_items");

        SavException ex = Assert.Throws<SavException>(
            () => OracleSqlBoundary.BuildWrappedCommand(
                OracleSqlTemplateKind.QuerySucceedsExists,
                ir,
                "SELECT upper(payload) FROM plan_items",
                policyAllowedFunctions: []));

        Assert.Equal(SavErrorCode.UnsupportedConstruct, ex.Code);
    }

    [Fact]
    public void Rejects_non_select_statement_types()
    {
        SqlIr ir = OracleTestIr.Create(
            statementTypes: ["Update"],
            agentSql: "UPDATE plan_items SET payload = 'x'");

        SavException ex = Assert.Throws<SavException>(
            () => OracleSqlBoundary.BuildWrappedCommand(
                OracleSqlTemplateKind.QuerySucceedsExists,
                ir,
                "UPDATE plan_items SET payload = 'x'",
                policyAllowedFunctions: []));

        Assert.Equal(SavErrorCode.UnsupportedConstruct, ex.Code);
    }
}
