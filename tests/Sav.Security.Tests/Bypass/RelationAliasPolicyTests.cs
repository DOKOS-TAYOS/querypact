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

public sealed class RelationAliasPolicyTests
{
    [Theory]
    [InlineData("SELECT sav_secret.sav_id FROM sav_src AS sav_secret", null)] // R06/C
    [InlineData("SELECT 1 FROM sav_src AS sav_blocked FOR UPDATE OF sav_blocked", null)] // R07/T
    [InlineData("SELECT a.sav_id FROM sav_src a", null)]
    [InlineData("SELECT sav_secret.sav_id FROM sav_src sav_secret WHERE EXISTS (SELECT 1 FROM sav_other sav_secret WHERE sav_secret.sav_id=1)", null)]
    [InlineData("SELECT 1 FROM app.sav_src sav_blocked WHERE EXISTS (SELECT 1 FROM audit.sav_other sav_blocked FOR SHARE OF sav_blocked) FOR UPDATE OF sav_blocked", null)]
    [InlineData("SELECT sav_secret FROM sav_src", "denied_column")]
    [InlineData("SELECT a.sav_secret FROM sav_src a", "denied_column")]
    [InlineData("SELECT app.sav_src.sav_secret FROM app.sav_src", "denied_column")]
    [InlineData("SELECT sav_secret.sav_id FROM sav_src sav_secret WHERE EXISTS (SELECT b.sav_secret FROM sav_other b WHERE b.sav_id=sav_secret.sav_id)", "denied_column")]
    [InlineData("SELECT 1 FROM sav_src a JOIN sav_other b ON a.sav_secret=b.sav_id", "denied_column")]
    [InlineData("SELECT 1 FROM sav_src a JOIN sav_other b USING (sav_secret)", "denied_column")]
    [InlineData("SELECT sav_blocked.sav_id FROM sav_src sav_blocked WHERE sav_blocked.sav_secret=1 FOR UPDATE OF sav_blocked", "denied_column")]
    [InlineData("SELECT sav_blocked.sav_id FROM sav_src sav_blocked ORDER BY sav_blocked.sav_secret FOR UPDATE OF sav_blocked", "denied_column")]
    [InlineData("SELECT 1 FROM sav_blocked a", "denied_table")]
    [InlineData("SELECT 1 FROM app.sav_blocked a FOR UPDATE OF a", "denied_table")]
    [InlineData("SELECT 1 FROM app.sav_src sav_blocked WHERE EXISTS (SELECT 1 FROM audit.sav_blocked b FOR SHARE OF b) FOR UPDATE OF sav_blocked", "denied_table")]
    public async Task Aliases_do_not_trigger_denials_but_referenced_columns_and_relations_do(string sql, string? rule)
    {
        AnalyzeSqlResponse response = await Analyze(sql);

        Assert.True(response.Analysis.IsParsable);
        Assert.Equal(rule is null ? PolicyOutcome.Allow : PolicyOutcome.Deny, response.Decision.Outcome);
        Assert.Equal(rule is null ? Array.Empty<string>() : [rule], response.Decision.RuleIds);
        Assert.Equal(response.Decision.RuleIds, response.Decision.Reasons);
        Assert.Equal(response.Decision.Reasons, response.RedactedReasons);
        Assert.All(response.Analysis.Ir.ColumnsRead, name => Assert.Equal("[REDACTED]", name));
        Assert.All(response.Analysis.Ir.TablesRead, name => Assert.Equal("[REDACTED]", name));
        Assert.All(response.Analysis.Ir.UnresolvedObjects, name => Assert.Equal("[REDACTED]", name));
        string json = CanonicalJson.Serialize(response);
        Assert.DoesNotContain("sav_secret", json);
        Assert.DoesNotContain("sav_blocked", json);
        Assert.DoesNotContain("sav_src", json);
        Assert.DoesNotContain("normalizedSql", json);
        Assert.Equal(json, CanonicalJson.Serialize(await Analyze(sql)));
    }

    [Fact]
    public async Task Lock_alias_correction_preserves_unresolved_denial_and_execution_boundary()
    {
        const string sql = "SELECT 1 FROM app.sav_src sav_blocked FOR UPDATE OF sav_blocked";
        AnalyzeSqlResponse response = await Analyze(sql, denyUnresolved: true);

        Assert.Equal(PolicyOutcome.Deny, response.Decision.Outcome);
        Assert.Equal(["unresolved_object"], response.Decision.RuleIds);
        var parsed = new LibPgQuerySqlParser().Parse(sql, CancellationToken.None);
        SavException error = Assert.Throws<SavException>(() => OracleSqlBoundary.BuildWrappedCommand(
            OracleSqlTemplateKind.QuerySucceedsExists, parsed.Ir!, sql, []));
        Assert.Equal(SavErrorCode.UnsupportedConstruct, error.Code);
    }

    private static async Task<AnalyzeSqlResponse> Analyze(string sql, bool denyUnresolved = false)
    {
        using var root = SecurityAnalyzeHarness.CreatePolicyRoot("valid-basic.yaml");
        string path = Path.Combine(root.Path, root.PolicyRelativePath);
        string policy = File.ReadAllText(path)
            .Replace("deniedColumns: []", "deniedColumns: [sav_secret]", StringComparison.Ordinal)
            .Replace("deniedTables: []", "deniedTables: [sav_blocked]", StringComparison.Ordinal);
        if (!denyUnresolved)
        {
            policy = policy.Replace("denyUnresolvedObjects: true", "denyUnresolvedObjects: false", StringComparison.Ordinal);
        }
        File.WriteAllText(path, policy);
        var useCase = new AnalyzeSqlUseCase(
            new LibPgQuerySqlParser(), new YamlPolicyEngine(), new YamlPolicyLoader(), new YamlContractLoader(),
            new ConfigPathResolver(new ConfigRootOptions { ConfigRoot = root.Path }), new StrictRedactor());
        return await useCase.ExecuteAsync(new(sql, root.PolicyRelativePath, null), CancellationToken.None);
    }
}
