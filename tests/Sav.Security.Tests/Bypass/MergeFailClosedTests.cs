using Sav.Application.Analyze;
using Sav.Domain.Decisions;
using Sav.Domain.Serialization;
using Sav.Infrastructure.Config;
using Sav.Infrastructure.Config.Paths;
using Sav.Infrastructure.Config.Policies;
using Sav.Infrastructure.Postgres.Parsing;
using Sav.Infrastructure.Postgres.Redaction;

namespace Sav.Security.Tests.Bypass;

public sealed class MergeFailClosedTests
{
    [Theory]
    [InlineData("MERGE INTO sav_dst d USING sav_src s ON d.id=s.id WHEN MATCHED THEN UPDATE SET value=s.value")]
    [InlineData("MERGE INTO sav_dst d USING sav_src s ON d.id=s.id WHEN NOT MATCHED THEN INSERT (id, value) VALUES (s.id, s.value)")]
    [InlineData("MERGE INTO sav_dst d USING sav_src s ON d.id=s.id WHEN MATCHED THEN DELETE")]
    [InlineData("MERGE INTO sav_dst d USING sav_src s ON d.id=s.id WHEN MATCHED THEN UPDATE SET value=s.value WHEN NOT MATCHED THEN INSERT (id, value) VALUES (s.id, s.value)")]
    public async Task Explicitly_allowed_merge_is_denied_only_as_unsupported(string sql)
    {
        AnalyzeSqlResponse response = await Analyze(sql, allowMerge: true);

        Assert.Equal(PolicyOutcome.Deny, response.Decision.Outcome);
        Assert.Equal(["unsupported_construct"], response.Decision.RuleIds);
        Assert.Equal(response.Decision.RuleIds, response.Decision.Reasons);
        Assert.Equal(response.Decision.Reasons, response.RedactedReasons);
        Assert.All(response.Analysis.Ir.TablesWritten, name => Assert.Equal("[REDACTED]", name));
        Assert.All(response.Analysis.Ir.TablesRead, name => Assert.Equal("[REDACTED]", name));
        string json = CanonicalJson.Serialize(response);
        Assert.DoesNotContain("sav_dst", json);
        Assert.DoesNotContain("sav_src", json);
        Assert.DoesNotContain("normalizedSql", json);
        Assert.Equal(json, CanonicalJson.Serialize(await Analyze(sql, allowMerge: true)));
    }

    [Fact]
    public async Task Denied_merge_destination_column_still_reports_unsupported_without_requiring_column_rule()
    {
        const string sql = "MERGE INTO sav_dst d USING sav_src s ON d.id=s.id WHEN MATCHED THEN UPDATE SET sav_secret=s.value";
        AnalyzeSqlResponse response = await Analyze(sql, allowMerge: true, deniedColumns: ["sav_secret"]);

        Assert.Equal(PolicyOutcome.Deny, response.Decision.Outcome);
        Assert.Equal(["unsupported_construct"], response.Decision.RuleIds);
        string json = CanonicalJson.Serialize(response);
        Assert.DoesNotContain("sav_secret", json);
        Assert.DoesNotContain("sav_dst", json);
        Assert.DoesNotContain("sav_src", json);
        Assert.DoesNotContain("normalizedSql", json);
        Assert.Equal(json, CanonicalJson.Serialize(await Analyze(sql, allowMerge: true, deniedColumns: ["sav_secret"])));
    }

    [Theory]
    [InlineData("EXPLAIN MERGE INTO sav_dst d USING sav_src s ON d.id=s.id WHEN MATCHED THEN DELETE")]
    [InlineData("EXPLAIN (ANALYZE) MERGE INTO sav_dst d USING sav_src s ON d.id=s.id WHEN MATCHED THEN DELETE")]
    public async Task Explicitly_allowed_explain_merge_is_denied_as_unsupported(string sql)
    {
        AnalyzeSqlResponse response = await Analyze(sql, allowMerge: false, allowExplain: true);

        Assert.Equal(PolicyOutcome.Deny, response.Decision.Outcome);
        Assert.Equal(["unsupported_construct"], response.Decision.RuleIds);
        Assert.Equal(response.Decision.Reasons, response.RedactedReasons);
    }

    [Theory]
    [InlineData("SELECT 1")]
    [InlineData("INSERT INTO sav_dst(id) SELECT id FROM sav_src")]
    [InlineData("UPDATE sav_dst SET value=1 WHERE id=2")]
    [InlineData("DELETE FROM sav_dst WHERE id=2")]
    public async Task Supported_top_level_dml_behavior_is_unchanged(string sql)
    {
        AnalyzeSqlResponse response = await Analyze(sql, allowMerge: false);

        Assert.Equal(PolicyOutcome.Allow, response.Decision.Outcome);
        Assert.Empty(response.Decision.RuleIds);
    }

    [Fact]
    public async Task Default_policy_rejects_merge_by_statement_type()
    {
        const string sql = "MERGE INTO sav_dst d USING sav_src s ON d.id=s.id WHEN MATCHED THEN DELETE";
        AnalyzeSqlResponse response = await Analyze(sql, allowMerge: false, useDefaultPolicy: true);

        Assert.Equal(PolicyOutcome.Deny, response.Decision.Outcome);
        Assert.Contains("forbidden_statement_type", response.Decision.RuleIds);
        Assert.Contains("unsupported_construct", response.Decision.RuleIds);
    }

    private static async Task<AnalyzeSqlResponse> Analyze(
        string sql,
        bool allowMerge,
        bool allowExplain = false,
        IReadOnlyList<string>? deniedColumns = null,
        bool useDefaultPolicy = false)
    {
        using var root = SecurityAnalyzeHarness.CreatePolicyRoot("valid-basic.yaml");
        string path = Path.Combine(root.Path, root.PolicyRelativePath);
        string policy = File.ReadAllText(path);
        if (!useDefaultPolicy)
        {
            policy = policy
                .Replace("  - Select", "  - Select\n  - Insert\n  - Update\n  - Delete" + (allowMerge ? "\n  - MergeStmt" : "") + (allowExplain ? "\n  - ExplainStmt" : ""), StringComparison.Ordinal)
                .Replace("denyUnresolvedObjects: true", "denyUnresolvedObjects: false", StringComparison.Ordinal);
            if (deniedColumns is { Count: > 0 })
            {
                policy = policy.Replace("deniedColumns: []", $"deniedColumns: [{string.Join(", ", deniedColumns)}]", StringComparison.Ordinal);
            }
        }

        File.WriteAllText(path, policy);
        var useCase = new AnalyzeSqlUseCase(
            new LibPgQuerySqlParser(), new YamlPolicyEngine(), new YamlPolicyLoader(), new YamlContractLoader(),
            new ConfigPathResolver(new ConfigRootOptions { ConfigRoot = root.Path }), new StrictRedactor());
        return await useCase.ExecuteAsync(new(sql, root.PolicyRelativePath, null), CancellationToken.None);
    }
}
