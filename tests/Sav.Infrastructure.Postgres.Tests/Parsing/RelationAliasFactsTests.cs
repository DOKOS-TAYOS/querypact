using Sav.Domain.Serialization;
using Sav.Infrastructure.Postgres.Parsing;

namespace Sav.Infrastructure.Postgres.Tests.Parsing;

public sealed class RelationAliasFactsTests
{
    [Theory]
    [InlineData("SELECT sav_secret.sav_id FROM sav_src AS sav_secret", "sav_id")] // R06
    [InlineData("SELECT sav_id FROM sav_src AS sav_secret", "sav_id")]
    [InlineData("SELECT app.sav_src.sav_id FROM app.sav_src", "sav_id")]
    [InlineData("SELECT sav_catalog.app.sav_src.sav_id FROM sav_catalog.app.sav_src", "sav_id")]
    [InlineData("SELECT sav_secret.\"sav.id\" FROM sav_src AS sav_secret", "sav.id")]
    [InlineData("SELECT sav_secret.sav_id + b.sav_value FROM sav_src sav_secret JOIN sav_other b ON sav_secret.sav_key=b.sav_key WHERE b.sav_filter=1 ORDER BY sav_secret.sav_order", "sav_filter", "sav_id", "sav_key", "sav_order", "sav_value")]
    [InlineData("SELECT a.sav_id FROM sav_src a JOIN sav_other b USING (sav_secret)", "sav_id", "sav_secret")]
    [InlineData("SELECT sav_secret.sav_id FROM sav_src sav_secret WHERE EXISTS (SELECT 1 FROM sav_other sav_secret WHERE sav_secret.sav_value=1)", "sav_id", "sav_value")]
    [InlineData("SELECT sav_secret.sav_id FROM sav_src sav_secret WHERE EXISTS (SELECT b.sav_secret FROM sav_other b WHERE b.sav_id=sav_secret.sav_id)", "sav_id", "sav_secret")]
    [InlineData("SELECT q.sav_id FROM (SELECT sav_secret.sav_id FROM sav_src sav_secret) q", "sav_id")]
    [InlineData("WITH sav_secret AS (SELECT sav_id FROM sav_src) SELECT sav_secret.sav_id FROM sav_secret", "sav_id")]
    [InlineData("SELECT sav_blocked.sav_id FROM app.sav_src sav_blocked WHERE sav_blocked.sav_filter=1 ORDER BY sav_blocked.sav_order LIMIT 2 FOR UPDATE OF sav_blocked", "sav_filter", "sav_id", "sav_order")]
    public void Only_column_components_and_join_keys_are_collected(string sql, params string[] columns)
    {
        var parsed = new LibPgQuerySqlParser().Parse(sql, CancellationToken.None);

        Assert.True(parsed.Success, parsed.RedactedMessage);
        Assert.Equal(columns, parsed.Ir!.ColumnsRead);
        Assert.Empty(parsed.Ir.ColumnsWritten);
        Assert.Empty(parsed.Ir.RiskCodes);
        Assert.Equal(CanonicalJson.Serialize(parsed.Ir), CanonicalJson.Serialize(
            new LibPgQuerySqlParser().Parse(sql, CancellationToken.None).Ir));
    }

    [Theory]
    [InlineData("SELECT 1 FROM sav_src AS sav_blocked FOR UPDATE OF sav_blocked", "sav_src")] // R07
    [InlineData("SELECT a.sav_id FROM sav_alpha a JOIN sav_beta b USING (sav_id) FOR NO KEY UPDATE OF a SKIP LOCKED", "sav_alpha", "sav_beta")] // E04
    [InlineData("SELECT 1 FROM app.sav_src sav_blocked FOR SHARE OF sav_blocked NOWAIT", "app.sav_src")]
    [InlineData("SELECT 1 FROM app.sav_src FOR KEY SHARE OF sav_src", "app.sav_src")]
    [InlineData("SELECT 1 FROM app.sav_src a, app.sav_other b FOR UPDATE OF a FOR SHARE OF b", "app.sav_other", "app.sav_src")]
    [InlineData("SELECT 1 FROM app.sav_src sav_blocked WHERE EXISTS (SELECT 1 FROM audit.sav_other sav_blocked FOR SHARE OF sav_blocked) FOR UPDATE OF sav_blocked", "app.sav_src", "audit.sav_other")]
    [InlineData("SELECT 1 FROM app.sav_src sav_blocked WHERE EXISTS (SELECT 1 FROM audit.sav_blocked b FOR SHARE OF b) FOR UPDATE OF sav_blocked", "app.sav_src", "audit.sav_blocked")]
    [InlineData("WITH sav_blocked AS (SELECT 1 FROM app.sav_src s FOR UPDATE OF s) SELECT 1 FROM sav_blocked FOR UPDATE OF sav_blocked", "app.sav_src")]
    [InlineData("WITH sav_blocked AS (SELECT 1) SELECT 1 FROM app.sav_blocked s FOR UPDATE OF s", "app.sav_blocked")]
    [InlineData("SELECT 1 FROM app.sav_src \"SAV_BLOCKED\" FOR UPDATE OF \"SAV_BLOCKED\"", "app.sav_src")]
    public void Lock_targets_do_not_declare_physical_relations(string sql, params string[] tables)
    {
        var parsed = new LibPgQuerySqlParser().Parse(sql, CancellationToken.None);

        Assert.True(parsed.Success, parsed.RedactedMessage);
        Assert.Equal(tables, parsed.Ir!.TablesRead);
        Assert.Equal(tables, parsed.Ir.UnresolvedObjects);
        Assert.Empty(parsed.Ir.TablesWritten);
        Assert.Empty(parsed.Ir.RiskCodes);
        Assert.Equal(["Select"], parsed.Ir.StatementTypes);
        Assert.False(parsed.Ir.HasMultipleStatements);
        Assert.False(parsed.Ir.HasDynamicSql);
    }
}
