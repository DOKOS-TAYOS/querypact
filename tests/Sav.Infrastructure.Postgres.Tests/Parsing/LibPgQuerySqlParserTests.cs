using System.Text.Json;
using Sav.Application.Abstractions;
using Sav.Infrastructure.Postgres.Parsing;

namespace Sav.Infrastructure.Postgres.Tests.Parsing;

public sealed class LibPgQuerySqlParserTests
{
    private readonly ISqlParser _parser = new LibPgQuerySqlParser();

    [Theory]
    [InlineData("")]
    [InlineData(" \t\r\n")]
    [InlineData("-- comment without SQL")]
    [InlineData("/* comment without SQL */")]
    [InlineData("/* outer /* nested */ comment */")]
    [InlineData("; ;")]
    public void Rejects_sql_without_executable_statements(string sql)
    {
        SqlParseResult result = _parser.Parse(sql, CancellationToken.None);

        Assert.False(result.Success);
        Assert.Null(result.Ir);
        Assert.Equal("sql_unparsable", result.ErrorCode);
    }

    [Fact]
    public void Leading_comment_does_not_hide_a_valid_statement()
    {
        SqlParseResult result = _parser.Parse(
            "/* leading comment */ SELECT 1",
            CancellationToken.None);

        Assert.True(result.Success, result.RedactedMessage);
        Assert.Single(result.Ir!.StatementTypes);
        Assert.Contains("Select", result.Ir.StatementTypes);
    }

    [Fact]
    public void Parses_simple_select_with_tables_and_columns()
    {
        SqlParseResult result = _parser.Parse(
            "SELECT id, email FROM users WHERE active = true",
            CancellationToken.None);

        Assert.True(result.Success);
        Assert.NotNull(result.Ir);
        Assert.Equal("postgresql", result.Ir.Dialect);
        Assert.Contains("Select", result.Ir.StatementTypes);
        Assert.Contains("users", result.Ir.TablesRead);
        Assert.Contains("id", result.Ir.ColumnsRead);
        Assert.Contains("email", result.Ir.ColumnsRead);
        Assert.False(result.Ir.HasMultipleStatements);
        Assert.False(string.IsNullOrWhiteSpace(result.Ir.NormalizedSql));
        Assert.False(string.IsNullOrWhiteSpace(result.Ir.Fingerprint));
    }

    [Fact]
    public void Preserves_quoted_relation_case_and_folds_unquoted_identifiers()
    {
        SqlParseResult unquoted = _parser.Parse(
            "SELECT id FROM MixedCaseRelation",
            CancellationToken.None);
        SqlParseResult quoted = _parser.Parse(
            "SELECT id FROM \"MixedCaseRelation\"",
            CancellationToken.None);

        Assert.True(unquoted.Success, unquoted.RedactedMessage);
        Assert.Contains("mixedcaserelation", unquoted.Ir!.TablesRead, StringComparer.Ordinal);
        Assert.True(quoted.Success, quoted.RedactedMessage);
        Assert.Contains("MixedCaseRelation", quoted.Ir!.TablesRead, StringComparer.Ordinal);
    }

    [Fact]
    public void Select_into_is_fail_closed_and_marks_write_target()
    {
        SqlParseResult result = _parser.Parse(
            "SELECT id INTO archived_users FROM users",
            CancellationToken.None);

        Assert.True(result.Success, result.RedactedMessage);
        Assert.Contains("Select", result.Ir!.StatementTypes);
        Assert.Contains("unsupported_construct", result.Ir.RiskCodes);
        Assert.Equal(["users"], result.Ir.TablesRead);
        Assert.Equal(["archived_users"], result.Ir.TablesWritten);
    }

    [Theory]
    [InlineData("MERGE INTO sav_dst d USING sav_src s ON d.id=s.id WHEN MATCHED THEN UPDATE SET value=s.value")]
    [InlineData("MERGE INTO sav_dst d USING sav_src s ON d.id=s.id WHEN NOT MATCHED THEN INSERT (id, value) VALUES (s.id, s.value)")]
    [InlineData("MERGE INTO sav_dst d USING sav_src s ON d.id=s.id WHEN MATCHED THEN DELETE")]
    [InlineData("MERGE INTO sav_dst d USING sav_src s ON d.id=s.id WHEN MATCHED THEN UPDATE SET value=s.value WHEN NOT MATCHED THEN INSERT (id, value) VALUES (s.id, s.value)")]
    public void Merge_is_parsed_with_statement_and_relation_facts_but_marked_unsupported(string sql)
    {
        SqlParseResult result = _parser.Parse(sql, CancellationToken.None);

        Assert.True(result.Success, result.RedactedMessage);
        Assert.Equal(["MergeStmt"], result.Ir!.StatementTypes);
        Assert.Contains("sav_dst", result.Ir.TablesWritten);
        Assert.Contains("sav_src", result.Ir.TablesRead);
        Assert.Contains("unsupported_construct", result.Ir.RiskCodes);
    }

    [Theory]
    [InlineData("EXPLAIN MERGE INTO sav_dst d USING sav_src s ON d.id=s.id WHEN MATCHED THEN DELETE")]
    [InlineData("EXPLAIN (ANALYZE) MERGE INTO sav_dst d USING sav_src s ON d.id=s.id WHEN MATCHED THEN DELETE")]
    public void Explain_merge_preserves_statement_and_relation_facts(string sql)
    {
        SqlParseResult result = _parser.Parse(sql, CancellationToken.None);

        Assert.True(result.Success, result.RedactedMessage);
        Assert.Equal(["ExplainStmt"], result.Ir!.StatementTypes);
        Assert.Contains("sav_dst", result.Ir.TablesWritten);
        Assert.Contains("sav_src", result.Ir.TablesRead);
        Assert.Contains("unsupported_construct", result.Ir.RiskCodes);
    }

    [Theory]
    [InlineData("CREATE TABLE sav_dst AS SELECT 1 FROM sav_src;")]
    [InlineData("CREATE MATERIALIZED VIEW sav_dst AS SELECT 1 FROM sav_src;")]
    public void Create_as_marks_only_the_destination_as_written(string sql)
    {
        SqlParseResult result = _parser.Parse(sql, CancellationToken.None);

        Assert.True(result.Success, result.RedactedMessage);
        Assert.Equal(["sav_src"], result.Ir!.TablesRead);
        Assert.Equal(["sav_dst"], result.Ir.TablesWritten);
        Assert.Equal(["sav_dst", "sav_src"], result.Ir.UnresolvedObjects);
        Assert.Equal(["CreateTableAsStmt"], result.Ir.StatementTypes);
        Assert.Empty(result.Ir.RiskCodes);
    }

    [Fact]
    public void Parses_cte_and_keeps_base_tables()
    {
        string sql = CorpusSql("cte");
        SqlParseResult result = _parser.Parse(sql, CancellationToken.None);

        Assert.True(result.Success);
        Assert.NotNull(result.Ir);
        Assert.Contains("users", result.Ir.TablesRead);
        Assert.Contains("orders", result.Ir.TablesRead);
        Assert.DoesNotContain("active_users", result.Ir.UnresolvedObjects);
    }

    [Fact]
    public void Nonrecursive_cte_does_not_hide_same_named_physical_relation_in_its_definition()
    {
        SqlParseResult result = _parser.Parse(
            "WITH v AS (SELECT id FROM v) SELECT id FROM v", CancellationToken.None);

        Assert.True(result.Success, result.RedactedMessage);
        Assert.Equal(["v"], result.Ir!.TablesRead);
        Assert.Equal(["v"], result.Ir.UnresolvedObjects);
    }

    [Fact]
    public void Cte_only_references_are_not_misclassified_as_physical_relations()
    {
        SqlParseResult result = _parser.Parse(
            "WITH v AS (SELECT 1 AS id) SELECT id FROM v", CancellationToken.None);

        Assert.True(result.Success, result.RedactedMessage);
        Assert.Empty(result.Ir!.TablesRead);
        Assert.Empty(result.Ir.UnresolvedObjects);
    }

    [Fact]
    public void Schema_qualified_relation_is_physical_even_when_a_cte_shadows_its_name()
    {
        SqlParseResult result = _parser.Parse(
            "WITH v AS (SELECT 1 AS id) SELECT id FROM public.v", CancellationToken.None);

        Assert.True(result.Success, result.RedactedMessage);
        Assert.Equal(["public.v"], result.Ir!.TablesRead);
        Assert.Equal(["public.v"], result.Ir.UnresolvedObjects);
    }

    [Fact]
    public void Nonrecursive_siblings_are_visible_in_definition_order()
    {
        SqlParseResult result = _parser.Parse(
            "WITH a AS (SELECT id FROM b), b AS (SELECT 1 AS id) SELECT id FROM a",
            CancellationToken.None);

        Assert.True(result.Success, result.RedactedMessage);
        Assert.Equal(["b"], result.Ir!.TablesRead);
        Assert.Equal(["b"], result.Ir.UnresolvedObjects);

        SqlParseResult earlier = _parser.Parse(
            "WITH b AS (SELECT 1 AS id), a AS (SELECT id FROM b) SELECT id FROM a",
            CancellationToken.None);
        Assert.True(earlier.Success, earlier.RedactedMessage);
        Assert.Empty(earlier.Ir!.TablesRead);
        Assert.Empty(earlier.Ir.UnresolvedObjects);
    }

    [Fact]
    public void Nested_and_recursive_cte_scopes_do_not_create_physical_relation_names()
    {
        SqlParseResult nested = _parser.Parse(
            "WITH v AS (SELECT 1 AS id) SELECT id FROM (WITH v AS (SELECT id FROM v) SELECT id FROM v) q",
            CancellationToken.None);
        Assert.True(nested.Success, nested.RedactedMessage);
        Assert.Empty(nested.Ir!.TablesRead);
        Assert.Empty(nested.Ir.UnresolvedObjects);

        SqlParseResult recursive = _parser.Parse(
            "WITH RECURSIVE seq(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM seq WHERE n < 3) SELECT n FROM seq",
            CancellationToken.None);
        Assert.True(recursive.Success, recursive.RedactedMessage);
        Assert.Empty(recursive.Ir!.TablesRead);
        Assert.Empty(recursive.Ir.UnresolvedObjects);
    }

    [Theory]
    [InlineData("WITH denied AS (SELECT 1) INSERT INTO denied DEFAULT VALUES")]
    [InlineData("WITH denied AS (SELECT 1) UPDATE denied SET id = 1 WHERE id = 0")]
    [InlineData("WITH denied AS (SELECT 1) DELETE FROM denied WHERE id = 0")]
    public void Cte_name_cannot_hide_physical_dml_target(string sql)
    {
        SqlParseResult result = _parser.Parse(sql, CancellationToken.None);

        Assert.True(result.Success, result.RedactedMessage);
        Assert.Contains("denied", result.Ir!.TablesWritten, StringComparer.Ordinal);
        Assert.Contains("denied", result.Ir.UnresolvedObjects, StringComparer.Ordinal);
    }

    [Fact]
    public void Parses_subquery_relation_reads()
    {
        SqlParseResult result = _parser.Parse(CorpusSql("subquery"), CancellationToken.None);

        Assert.True(result.Success);
        Assert.NotNull(result.Ir);
        Assert.Contains("users", result.Ir.TablesRead);
        Assert.Contains("orders", result.Ir.TablesRead);
    }

    [Fact]
    public void Parses_table_alias_without_treating_alias_as_table()
    {
        SqlParseResult result = _parser.Parse(CorpusSql("alias"), CancellationToken.None);

        Assert.True(result.Success);
        Assert.NotNull(result.Ir);
        Assert.Contains("users", result.Ir.TablesRead);
        Assert.DoesNotContain("u", result.Ir.TablesRead);
        Assert.Contains("id", result.Ir.ColumnsRead);
    }

    [Fact]
    public void Extracts_functions()
    {
        SqlParseResult result = _parser.Parse(CorpusSql("function"), CancellationToken.None);

        Assert.True(result.Success);
        Assert.NotNull(result.Ir);
        Assert.Contains("lower", result.Ir.Functions, StringComparer.OrdinalIgnoreCase);
        Assert.Contains("count", result.Ir.Functions, StringComparer.OrdinalIgnoreCase);
    }

    [Fact]
    public void Canonicalizes_schema_qualified_functions_without_splitting_components()
    {
        SqlParseResult result = _parser.Parse(
            "SELECT pg_catalog.lower(email), private.lower(email) FROM users",
            CancellationToken.None);

        Assert.True(result.Success);
        Assert.NotNull(result.Ir);
        Assert.Equal(2, result.Ir.Functions.Count);
        Assert.Contains("lower", result.Ir.Functions, StringComparer.OrdinalIgnoreCase);
        Assert.Contains("private.lower", result.Ir.Functions, StringComparer.OrdinalIgnoreCase);
        Assert.DoesNotContain("pg_catalog", result.Ir.Functions, StringComparer.OrdinalIgnoreCase);
        Assert.DoesNotContain("private", result.Ir.Functions, StringComparer.OrdinalIgnoreCase);

        SqlParseResult quoted = _parser.Parse(
            "SELECT \"PG_CATALOG\".lower(email) FROM users",
            CancellationToken.None);
        Assert.True(quoted.Success);
        Assert.Contains("PG_CATALOG.lower", quoted.Ir!.Functions, StringComparer.Ordinal);
    }

    [Fact]
    public void Extracts_operator_names_for_live_catalog_validation()
    {
        SqlParseResult result = _parser.Parse(
            "SELECT 1 === 1, 2 OPERATOR(pg_catalog.+) 3, 4 OPERATOR(public.##) 5",
            CancellationToken.None);

        Assert.True(result.Success, result.RedactedMessage);
        Assert.NotNull(result.Ir);
        Assert.Contains("===", result.Ir.Operators, StringComparer.Ordinal);
        Assert.Contains("pg_catalog.+", result.Ir.Operators, StringComparer.Ordinal);
        Assert.Contains("public.##", result.Ir.Operators, StringComparer.Ordinal);
    }

    [Fact]
    public void Extracts_sort_using_and_quantified_sublink_operators()
    {
        SqlParseResult sort = _parser.Parse(
            "SELECT id FROM users ORDER BY id USING ===",
            CancellationToken.None);
        SqlParseResult sublink = _parser.Parse(
            "SELECT 1 === ANY (SELECT id FROM users)",
            CancellationToken.None);

        Assert.True(sort.Success, sort.RedactedMessage);
        Assert.Contains("===", sort.Ir!.Operators, StringComparer.Ordinal);
        Assert.True(sublink.Success, sublink.RedactedMessage);
        Assert.Contains("===", sublink.Ir!.Operators, StringComparer.Ordinal);
    }

    [Fact]
    public void Identifies_insert_write_target()
    {
        SqlParseResult result = _parser.Parse(CorpusSql("insert"), CancellationToken.None);

        Assert.True(result.Success);
        Assert.NotNull(result.Ir);
        Assert.Contains("Insert", result.Ir.StatementTypes);
        Assert.Contains("users", result.Ir.TablesWritten);
    }

    [Fact]
    public void Extracts_insert_and_update_write_target_columns()
    {
        SqlParseResult insert = _parser.Parse(
            "INSERT INTO users (id, ssn) VALUES (1, 'x')",
            CancellationToken.None);
        SqlParseResult update = _parser.Parse(
            "UPDATE users SET ssn = 'x', email = 'y' WHERE id = 1",
            CancellationToken.None);

        Assert.True(insert.Success, insert.RedactedMessage);
        Assert.Contains("id", insert.Ir!.ColumnsWritten, StringComparer.OrdinalIgnoreCase);
        Assert.Contains("ssn", insert.Ir.ColumnsWritten, StringComparer.OrdinalIgnoreCase);

        Assert.True(update.Success, update.RedactedMessage);
        Assert.Contains("ssn", update.Ir!.ColumnsWritten, StringComparer.OrdinalIgnoreCase);
        Assert.Contains("email", update.Ir.ColumnsWritten, StringComparer.OrdinalIgnoreCase);
    }

    [Fact]
    public void Keeps_dml_source_columns_out_of_write_targets()
    {
        SqlParseResult result = _parser.Parse(
            "UPDATE users SET email = (SELECT profile_email FROM profiles WHERE profiles.id = users.id) WHERE users.id = 1",
            CancellationToken.None);

        Assert.True(result.Success, result.RedactedMessage);
        Assert.Contains("email", result.Ir!.ColumnsWritten, StringComparer.OrdinalIgnoreCase);
        Assert.Contains("profile_email", result.Ir.ColumnsRead, StringComparer.OrdinalIgnoreCase);
        Assert.DoesNotContain("profile_email", result.Ir.ColumnsWritten, StringComparer.OrdinalIgnoreCase);
    }

    [Fact]
    public void Extracts_on_conflict_update_write_target_columns()
    {
        SqlParseResult result = _parser.Parse(
            "INSERT INTO users (id) VALUES (1) ON CONFLICT (id) DO UPDATE SET ssn = 'x', email = excluded.email",
            CancellationToken.None);

        Assert.True(result.Success, result.RedactedMessage);
        Assert.Contains("id", result.Ir!.ColumnsWritten, StringComparer.OrdinalIgnoreCase);
        Assert.Contains("ssn", result.Ir.ColumnsWritten, StringComparer.OrdinalIgnoreCase);
        Assert.Contains("email", result.Ir.ColumnsWritten, StringComparer.OrdinalIgnoreCase);
    }

    [Fact]
    public void Detects_update_and_delete_predicate_presence()
    {
        SqlParseResult withPred = _parser.Parse(CorpusSql("update_with_predicate"), CancellationToken.None);
        SqlParseResult withoutPred = _parser.Parse(CorpusSql("update_without_predicate"), CancellationToken.None);
        SqlParseResult deleteWith = _parser.Parse(CorpusSql("delete_with_predicate"), CancellationToken.None);
        SqlParseResult deleteWithout = _parser.Parse(CorpusSql("delete_without_predicate"), CancellationToken.None);

        Assert.True(withPred.Success);
        Assert.DoesNotContain("missing_predicate", withPred.Ir!.RiskCodes);
        Assert.True(withoutPred.Success);
        Assert.Contains("missing_predicate", withoutPred.Ir!.RiskCodes);
        Assert.True(deleteWith.Success);
        Assert.DoesNotContain("missing_predicate", deleteWith.Ir!.RiskCodes);
        Assert.True(deleteWithout.Success);
        Assert.Contains("missing_predicate", deleteWithout.Ir!.RiskCodes);
    }

    [Fact]
    public void Nested_predicates_do_not_satisfy_outer_update_or_delete_predicate_requirement()
    {
        SqlParseResult update = _parser.Parse(
            "UPDATE users SET email = (SELECT email FROM profiles WHERE profiles.id = users.id)",
            CancellationToken.None);
        SqlParseResult delete = _parser.Parse(
            "DELETE FROM users USING (SELECT id FROM profiles WHERE active = true) AS filtered",
            CancellationToken.None);

        Assert.True(update.Success, update.RedactedMessage);
        Assert.Contains("missing_predicate", update.Ir!.RiskCodes);
        Assert.True(delete.Success, delete.RedactedMessage);
        Assert.Contains("missing_predicate", delete.Ir!.RiskCodes);
    }

    [Fact]
    public void Detects_multiple_statements()
    {
        SqlParseResult result = _parser.Parse(CorpusSql("multi_statement"), CancellationToken.None);

        Assert.True(result.Success);
        Assert.NotNull(result.Ir);
        Assert.True(result.Ir.HasMultipleStatements);
    }

    [Fact]
    public void Invalid_sql_fails_closed_with_redacted_error()
    {
        SqlParseResult result = _parser.Parse(CorpusSql("invalid"), CancellationToken.None);

        Assert.False(result.Success);
        Assert.Null(result.Ir);
        Assert.Equal("sql_unparsable", result.ErrorCode);
        Assert.False(string.IsNullOrWhiteSpace(result.RedactedMessage));
        Assert.DoesNotContain("leak@example.invalid", result.RedactedMessage, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("'leak", result.RedactedMessage, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Select_star_marks_unsupported_construct()
    {
        SqlParseResult result = _parser.Parse(CorpusSql("select_star"), CancellationToken.None);

        Assert.True(result.Success);
        Assert.NotNull(result.Ir);
        Assert.Contains("unsupported_construct", result.Ir.RiskCodes);
    }

    [Fact]
    public void Maps_schema_qualified_dml_and_unsupported_statement_families()
    {
        SqlParseResult dml = _parser.Parse(
            "INSERT INTO app.users (id, email) VALUES (1, 'x'); UPDATE app.users SET email = 'y' WHERE id = 1; DELETE FROM app.sessions WHERE user_id = 1",
            CancellationToken.None);

        Assert.True(dml.Success, dml.RedactedMessage);
        Assert.NotNull(dml.Ir);
        Assert.Equal(["Insert", "Update", "Delete"], dml.Ir.StatementTypes);
        Assert.Contains("app.users", dml.Ir.TablesWritten);
        Assert.Contains("app.sessions", dml.Ir.TablesWritten);
        Assert.True(dml.Ir.HasMultipleStatements);

        SqlParseResult prepare = _parser.Parse("PREPARE q(int) AS SELECT id FROM app.users WHERE id = $1", CancellationToken.None);
        Assert.True(prepare.Success, prepare.RedactedMessage);
        Assert.Contains("Prepare", prepare.Ir!.StatementTypes);
        Assert.True(prepare.Ir.HasDynamicSql);
        Assert.Contains("unsupported_construct", prepare.Ir.RiskCodes);

        SqlParseResult copy = _parser.Parse("COPY app.users TO STDOUT", CancellationToken.None);
        Assert.True(copy.Success, copy.RedactedMessage);
        Assert.Contains("Copy", copy.Ir!.StatementTypes);
        Assert.True(copy.Ir.HasDynamicSql);
        Assert.Contains("unsupported_construct", copy.Ir.RiskCodes);
    }

    [Fact]
    public void Honors_cancellation_before_parse()
    {
        using CancellationTokenSource cts = new();
        cts.Cancel();
        Assert.ThrowsAny<OperationCanceledException>(() => _parser.Parse("SELECT 1", cts.Token));
    }

    private static string CorpusSql(string id)
    {
        string path = FixturePath.AdversarialCorpus();
        using FileStream stream = File.OpenRead(path);
        using JsonDocument doc = JsonDocument.Parse(stream);
        foreach (JsonElement item in doc.RootElement.GetProperty("cases").EnumerateArray())
        {
            if (string.Equals(item.GetProperty("id").GetString(), id, StringComparison.Ordinal))
            {
                return item.GetProperty("sql").GetString()
                    ?? throw new InvalidOperationException("Missing sql for " + id);
            }
        }

        throw new InvalidOperationException("Corpus case not found: " + id);
    }
}

internal static class FixturePath
{
    public static string AdversarialCorpus()
    {
        string? dir = new DirectoryInfo(AppContext.BaseDirectory).FullName;
        DirectoryInfo? cursor = new(dir);
        while (cursor is not null)
        {
            string candidate = Path.Combine(cursor.FullName, "tests", "fixtures", "sql", "adversarial-corpus.json");
            if (File.Exists(candidate))
            {
                return candidate;
            }

            cursor = cursor.Parent;
        }

        throw new FileNotFoundException("adversarial-corpus.json");
    }
}
