using Sav.Application.Analyze;
using Sav.Domain.Decisions;
using Sav.Domain.Errors;
using Sav.Domain.Serialization;
using Sav.Infrastructure.Config;
using Sav.Infrastructure.Config.Paths;
using Sav.Infrastructure.Config.Policies;
using Sav.Infrastructure.Postgres.Oracle;
using Sav.Infrastructure.Postgres.Parsing;
using Sav.Infrastructure.Postgres.Redaction;

namespace Sav.Security.Tests.Bypass;

public sealed class ModifyingCtePolicyTests
{
    [Theory]
    [InlineData("SELECT 1 FROM sav_src TABLESAMPLE SYSTEM (10)", false)]
    [InlineData("WITH sav_w AS (INSERT INTO sav_dst(sav_id) SELECT sav_id FROM sav_src TABLESAMPLE SYSTEM (10)) SELECT 1", true)]
    public async Task Tablesample_preserves_policy_and_modifying_cte_fail_closed_behavior(string sql, bool modifyingCte)
    {
        var parsed = new LibPgQuerySqlParser().Parse(sql, CancellationToken.None);
        Assert.True(parsed.Success, parsed.RedactedMessage);
        Assert.Equal(["sav_src"], parsed.Ir!.TablesRead);
        Assert.Equal(modifyingCte ? ["sav_dst"] : Array.Empty<string>(), parsed.Ir.TablesWritten);
        Assert.Equal(modifyingCte ? ["unsupported_construct"] : Array.Empty<string>(), parsed.Ir.RiskCodes);

        AnalyzeSqlResponse response = await Analyze(sql);

        Assert.Equal(modifyingCte ? PolicyOutcome.Deny : PolicyOutcome.Allow, response.Decision.Outcome);
        Assert.Equal(modifyingCte ? ["unsupported_construct"] : Array.Empty<string>(), response.Decision.RuleIds);
        if (modifyingCte)
        {
            SavException error = Assert.Throws<SavException>(() => OracleSqlBoundary.BuildWrappedCommand(
                OracleSqlTemplateKind.QuerySucceedsExists, parsed.Ir, sql, []));
            Assert.Equal(SavErrorCode.UnsupportedConstruct, error.Code);
        }
    }

    [Theory]
    [InlineData("INSERT INTO sav_dst(sav_secret) VALUES (1)")]
    [InlineData("UPDATE sav_dst SET sav_secret=1")] // R11
    [InlineData("INSERT INTO sav_dst(sav_id) VALUES (1) ON CONFLICT (sav_id) DO UPDATE SET sav_secret=2")]
    public async Task Explicit_nested_targets_independently_trigger_denied_column(string dml)
    {
        string sql = $"WITH sav_w AS ({dml}) SELECT 1 WHERE false";
        var parsed = new LibPgQuerySqlParser().Parse(sql, CancellationToken.None);
        Assert.True(parsed.Success, parsed.RedactedMessage);
        Assert.DoesNotContain("sav_secret", parsed.Ir!.ColumnsRead);

        AnalyzeSqlResponse response = await Analyze(sql);

        Assert.Equal(PolicyOutcome.Deny, response.Decision.Outcome);
        Assert.Equal(["denied_column", "unsupported_construct"], response.Decision.RuleIds);
        Assert.Equal(response.Decision.RuleIds, response.Decision.Reasons);
        Assert.Equal(response.Decision.Reasons, response.RedactedReasons);
        Assert.All(response.Analysis.Ir.ColumnsWritten, name => Assert.Equal("[REDACTED]", name));
        Assert.All(response.Analysis.Ir.TablesWritten, name => Assert.Equal("[REDACTED]", name));
        string json = CanonicalJson.Serialize(response);
        Assert.DoesNotContain("sav_secret", json);
        Assert.DoesNotContain("sav_dst", json);
        Assert.DoesNotContain("normalizedSql", json);
        Assert.Equal(json, CanonicalJson.Serialize(await Analyze(sql)));
    }

    [Theory]
    [InlineData("WITH sav_w AS (INSERT INTO sav_dst(sav_id) VALUES (1)) SELECT 1")]
    [InlineData("WITH sav_w AS (UPDATE sav_dst SET sav_value=1 WHERE sav_id=2) SELECT 1")]
    [InlineData("WITH sav_w AS (DELETE FROM sav_dst USING sav_src WHERE sav_dst.sav_id=sav_src.sav_id) SELECT 1")]
    [InlineData("WITH sav_w AS (INSERT INTO sav_dst(sav_id) VALUES (1) ON CONFLICT (sav_id) DO UPDATE SET sav_value=2) SELECT 1 WHERE false")]
    [InlineData("WITH sav_w AS (UPDATE sav_dst SET sav_value=1 RETURNING sav_value AS sav_secret) SELECT 1")]
    public async Task Modifying_ctes_without_denied_targets_remain_fail_closed(string sql)
    {
        AnalyzeSqlResponse response = await Analyze(sql);

        Assert.Equal(PolicyOutcome.Deny, response.Decision.Outcome);
        Assert.Equal(["unsupported_construct"], response.Decision.RuleIds);
        var parsed = new LibPgQuerySqlParser().Parse(sql, CancellationToken.None);
        SavException error = Assert.Throws<SavException>(() => OracleSqlBoundary.BuildWrappedCommand(
            OracleSqlTemplateKind.QuerySucceedsExists, parsed.Ir!, sql, []));
        Assert.Equal(SavErrorCode.UnsupportedConstruct, error.Code);
    }

    [Theory]
    [InlineData("WITH sav_w AS (INSERT INTO sav_dst(sav_value) SELECT sav_secret FROM sav_src) SELECT 1")]
    [InlineData("WITH sav_w AS (UPDATE sav_dst SET sav_value=sav_secret WHERE sav_id=1) SELECT 1")]
    [InlineData("WITH sav_w AS (DELETE FROM sav_dst WHERE sav_secret=1 RETURNING sav_id) SELECT 1")]
    [InlineData("WITH sav_w AS (UPDATE sav_dst SET sav_value=1 RETURNING sav_secret) SELECT 1")]
    public async Task Denied_expression_predicate_and_returning_reads_still_trigger_denied_column(string sql)
    {
        var parsed = new LibPgQuerySqlParser().Parse(sql, CancellationToken.None);
        Assert.Contains("sav_secret", parsed.Ir!.ColumnsRead);
        Assert.DoesNotContain("sav_secret", parsed.Ir.ColumnsWritten);

        AnalyzeSqlResponse response = await Analyze(sql);
        Assert.Equal(PolicyOutcome.Deny, response.Decision.Outcome);
        Assert.Equal(["denied_column", "unsupported_construct"], response.Decision.RuleIds);
    }

    [Theory]
    [InlineData("INSERT INTO sav_dst(sav_id) SELECT sav_id FROM sav_src")]
    [InlineData("UPDATE sav_dst SET sav_value=1 FROM sav_src WHERE sav_dst.sav_id=sav_src.sav_id")]
    [InlineData("DELETE FROM sav_dst USING sav_src WHERE sav_dst.sav_id=sav_src.sav_id")]
    public async Task Supported_top_level_dml_remains_allowed_when_authorized(string sql)
    {
        AnalyzeSqlResponse response = await Analyze(sql);

        Assert.Equal(PolicyOutcome.Allow, response.Decision.Outcome);
        Assert.Empty(response.Decision.RuleIds);
    }

    private static async Task<AnalyzeSqlResponse> Analyze(string sql)
    {
        using var root = SecurityAnalyzeHarness.CreatePolicyRoot("valid-basic.yaml");
        string path = Path.Combine(root.Path, root.PolicyRelativePath);
        File.WriteAllText(path, File.ReadAllText(path)
            .Replace("  - Select", "  - Select\n  - Insert\n  - Update\n  - Delete", StringComparison.Ordinal)
            .Replace("deniedColumns: []", "deniedColumns: [sav_secret]", StringComparison.Ordinal)
            .Replace("denyUnresolvedObjects: true", "denyUnresolvedObjects: false", StringComparison.Ordinal));
        var useCase = new AnalyzeSqlUseCase(
            new LibPgQuerySqlParser(), new YamlPolicyEngine(), new YamlPolicyLoader(), new YamlContractLoader(),
            new ConfigPathResolver(new ConfigRootOptions { ConfigRoot = root.Path }), new StrictRedactor());
        return await useCase.ExecuteAsync(new(sql, root.PolicyRelativePath, null), CancellationToken.None);
    }
}
