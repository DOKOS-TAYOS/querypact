using Sav.Domain.Serialization;
using Sav.Infrastructure.Postgres.Parsing;

namespace Sav.Infrastructure.Postgres.Tests.Parsing;

public sealed class ModifyingCteFactsTests
{
    [Theory]
    [InlineData("SELECT 1 FROM sav_src TABLESAMPLE SYSTEM (10)", false)]
    [InlineData("WITH sav_w AS (INSERT INTO sav_dst(sav_id) SELECT sav_id FROM sav_src TABLESAMPLE SYSTEM (10)) SELECT 1", true)]
    public void Tablesample_relations_are_read_only_sources(string sql, bool modifyingCte)
    {
        var parsed = new LibPgQuerySqlParser().Parse(sql, CancellationToken.None);

        Assert.True(parsed.Success, parsed.RedactedMessage);
        Assert.Equal(["Select"], parsed.Ir!.StatementTypes);
        Assert.Equal(["sav_src"], parsed.Ir.TablesRead);
        Assert.Equal(modifyingCte ? ["sav_dst"] : Array.Empty<string>(), parsed.Ir.TablesWritten);
        Assert.Equal(modifyingCte ? ["sav_dst", "sav_src"] : ["sav_src"], parsed.Ir.UnresolvedObjects);
        Assert.Equal(modifyingCte ? ["sav_id"] : Array.Empty<string>(), parsed.Ir.ColumnsRead);
        Assert.Equal(modifyingCte ? ["sav_id"] : Array.Empty<string>(), parsed.Ir.ColumnsWritten);
        Assert.Equal(modifyingCte ? ["unsupported_construct"] : Array.Empty<string>(), parsed.Ir.RiskCodes);
        Assert.False(parsed.Ir.HasMultipleStatements);
        Assert.False(parsed.Ir.HasDynamicSql);
    }

    [Theory]
    [InlineData("WITH sav_w AS (INSERT INTO sav_dst(sav_id) VALUES (1)) SELECT 1", "sav_id")] // R04
    [InlineData("WITH sav_w AS (INSERT INTO sav_dst (sav_id) VALUES (1) RETURNING sav_id) SELECT sav_id FROM sav_w", "sav_id")] // W01
    [InlineData("WITH sav_w AS (UPDATE sav_dst SET sav_value = 1 WHERE sav_id = 2 RETURNING sav_id) SELECT sav_id FROM sav_w", "sav_value")] // W02
    [InlineData("WITH sav_w AS (UPDATE sav_dst SET sav_secret=1) SELECT 1", "sav_secret")] // R11
    [InlineData("WITH sav_w AS (INSERT INTO sav_dst(sav_id) VALUES (1) ON CONFLICT (sav_id) DO UPDATE SET sav_value=2 RETURNING sav_id) SELECT 1 WHERE false", "sav_id", "sav_value")] // H01
    [InlineData("WITH sav_dst AS (SELECT 1 AS sav_id), sav_w AS (INSERT INTO sav_dst(sav_id) VALUES (1) RETURNING sav_id) SELECT sav_id FROM sav_w", "sav_id")] // Q06
    public void Collects_nested_explicit_write_targets(string sql, params string[] expected)
    {
        var parsed = new LibPgQuerySqlParser().Parse(sql, CancellationToken.None);

        Assert.True(parsed.Success, parsed.RedactedMessage);
        Assert.Equal(expected, parsed.Ir!.ColumnsWritten);
        Assert.Equal(["sav_dst"], parsed.Ir.TablesWritten);
        Assert.Empty(parsed.Ir.TablesRead);
        Assert.Equal(["sav_dst"], parsed.Ir.UnresolvedObjects);
        Assert.Equal(["Select"], parsed.Ir.StatementTypes);
        Assert.False(parsed.Ir.HasMultipleStatements);
        Assert.Equal(["unsupported_construct"], parsed.Ir.RiskCodes);
    }

    [Theory]
    [InlineData("INSERT INTO sav_dst SELECT 1 FROM sav_src")] // R05
    [InlineData("INSERT INTO sav_dst (sav_id) SELECT sav_id FROM sav_src RETURNING sav_id")] // W04
    [InlineData("UPDATE sav_dst SET sav_value = sav_src.sav_value FROM sav_src WHERE sav_dst.sav_id = sav_src.sav_id RETURNING sav_dst.sav_id")] // W05
    [InlineData("DELETE FROM sav_dst USING sav_src WHERE sav_dst.sav_id = sav_src.sav_id RETURNING sav_dst.sav_id")] // W06
    [InlineData("UPDATE sav_dst SET sav_value = (SELECT sav_value FROM sav_src) WHERE sav_id = 1")]
    [InlineData("DELETE FROM sav_dst WHERE EXISTS (SELECT 1 FROM sav_src WHERE sav_src.sav_id = sav_dst.sav_id)")]
    public void Classifies_sources_as_reads_at_top_level_and_in_modifying_ctes(string dml)
    {
        var parser = new LibPgQuerySqlParser();
        foreach (bool nested in new[] { false, true })
        {
            string sql = nested ? $"WITH sav_w AS ({dml}) SELECT 1" : dml;
            var parsed = parser.Parse(sql, CancellationToken.None);

            Assert.True(parsed.Success, parsed.RedactedMessage);
            Assert.Equal(["sav_src"], parsed.Ir!.TablesRead);
            Assert.Equal(["sav_dst"], parsed.Ir.TablesWritten);
            Assert.Equal(["sav_dst", "sav_src"], parsed.Ir.UnresolvedObjects);
            Assert.Equal(nested ? ["unsupported_construct"] : Array.Empty<string>(), parsed.Ir.RiskCodes);
        }
    }

    [Theory]
    [InlineData("INSERT INTO sav_dst (sav_target) SELECT sav_input FROM sav_src WHERE sav_filter = 1 RETURNING sav_output")]
    [InlineData("UPDATE sav_dst SET sav_target = (SELECT sav_input FROM sav_src WHERE sav_filter = 1) WHERE sav_predicate = 2 RETURNING sav_output")]
    [InlineData("INSERT INTO sav_dst DEFAULT VALUES ON CONFLICT (sav_key) DO UPDATE SET sav_target = (SELECT sav_input FROM sav_src WHERE sav_filter = 1) WHERE sav_predicate = 2 RETURNING sav_output")]
    [InlineData("UPDATE sav_dst SET (sav_target, sav_other) = (SELECT sav_input, sav_second FROM sav_src WHERE sav_filter = 1) WHERE sav_predicate = 2 RETURNING sav_output")]
    public void Assignment_targets_are_distinct_from_expression_predicate_and_returning_reads(string dml)
    {
        foreach (bool nested in new[] { false, true })
        {
            string sql = nested ? $"WITH sav_w AS ({dml}) SELECT 1" : dml;
            var parsed = new LibPgQuerySqlParser().Parse(sql, CancellationToken.None);

            Assert.True(parsed.Success, parsed.RedactedMessage);
            Assert.Contains("sav_target", parsed.Ir!.ColumnsWritten);
            Assert.DoesNotContain("sav_target", parsed.Ir.ColumnsRead);
            Assert.Contains("sav_input", parsed.Ir.ColumnsRead);
            Assert.Contains("sav_filter", parsed.Ir.ColumnsRead);
            Assert.Contains("sav_output", parsed.Ir.ColumnsRead);
            Assert.All(parsed.Ir.ColumnsWritten, name => Assert.Contains(name, new[] { "sav_other", "sav_target" }));
            Assert.Equal(["sav_src"], parsed.Ir.TablesRead);
            Assert.Equal(["sav_dst"], parsed.Ir.TablesWritten);
            Assert.Equal(CanonicalJson.Serialize(parsed.Ir), CanonicalJson.Serialize(
                new LibPgQuerySqlParser().Parse(sql, CancellationToken.None).Ir));
        }
    }

    [Theory]
    [InlineData("WITH sav_dst AS (SELECT 1 AS sav_id), sav_w AS (INSERT INTO sav_dst(sav_id) SELECT sav_id FROM sav_dst) SELECT 1")]
    [InlineData("WITH sav_dst AS (SELECT 1 AS sav_id) INSERT INTO sav_dst(sav_id) SELECT sav_id FROM sav_dst")]
    [InlineData("WITH sav_src AS (SELECT 1 AS sav_id), sav_w AS (INSERT INTO sav_dst(sav_id) SELECT sav_id FROM sav_src) SELECT 1")]
    [InlineData("WITH RECURSIVE sav_src(sav_id) AS (SELECT 1 UNION ALL SELECT sav_id + 1 FROM sav_src WHERE sav_id < 3), sav_w AS (INSERT INTO sav_dst(sav_id) SELECT sav_id FROM sav_src) SELECT 1")]
    public void Cte_sources_do_not_become_physical_reads_even_when_the_destination_has_the_same_name(string sql)
    {
        var parsed = new LibPgQuerySqlParser().Parse(sql, CancellationToken.None);

        Assert.True(parsed.Success, parsed.RedactedMessage);
        Assert.Empty(parsed.Ir!.TablesRead);
        Assert.Equal(["sav_dst"], parsed.Ir.TablesWritten);
        Assert.Equal(["sav_dst"], parsed.Ir.UnresolvedObjects);
    }

    [Theory]
    [InlineData("WITH sav_src AS (SELECT sav_id FROM sav_src), sav_w AS (INSERT INTO sav_dst(sav_id) SELECT sav_id FROM sav_src) SELECT 1", "sav_src")]
    [InlineData("WITH sav_src AS (SELECT 1 AS sav_id), sav_w AS (INSERT INTO sav_dst(sav_id) SELECT sav_id FROM app.sav_src) SELECT 1", "app.sav_src")]
    [InlineData("WITH sav_w AS (INSERT INTO sav_dst(sav_id) SELECT sav_id FROM (WITH sav_src AS (SELECT sav_id FROM app.sav_src) SELECT sav_id FROM sav_src) q) SELECT 1", "app.sav_src")]
    [InlineData("WITH sav_w AS (INSERT INTO sav_dst(sav_id) SELECT sav_id FROM sav_src), sav_src AS (SELECT 1 AS sav_id) SELECT 1", "sav_src")]
    public void Modifying_cte_sources_preserve_lexical_scope_and_physical_identity(string sql, string source)
    {
        var parsed = new LibPgQuerySqlParser().Parse(sql, CancellationToken.None);

        Assert.True(parsed.Success, parsed.RedactedMessage);
        Assert.Equal([source], parsed.Ir!.TablesRead);
        Assert.Equal(["sav_dst"], parsed.Ir.TablesWritten);
        Assert.Equal(new[] { source, "sav_dst" }.Order(StringComparer.Ordinal), parsed.Ir.UnresolvedObjects);
    }

    [Fact]
    public void A_relation_used_as_both_a_source_and_destination_keeps_both_roles()
    {
        const string sql = "WITH sav_w AS (INSERT INTO sav_dst(sav_id) SELECT sav_id FROM sav_dst) SELECT 1";
        var parsed = new LibPgQuerySqlParser().Parse(sql, CancellationToken.None);

        Assert.True(parsed.Success, parsed.RedactedMessage);
        Assert.Equal(["sav_dst"], parsed.Ir!.TablesRead);
        Assert.Equal(["sav_dst"], parsed.Ir.TablesWritten);
        Assert.Equal(["sav_dst"], parsed.Ir.UnresolvedObjects);
    }
}
