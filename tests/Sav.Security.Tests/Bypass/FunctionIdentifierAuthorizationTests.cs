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

public sealed class FunctionIdentifierAuthorizationTests
{
    [Theory]
    [InlineData("SELECT sav_scope.\"SAV_SAFE_FN\"()")]
    [InlineData("SELECT \"SAV_SCOPE\".sav_safe_fn()")]
    [InlineData("SELECT sav_scope.sav_safe_fn(), sav_scope.\"SAV_SAFE_FN\"()")]
    public void Oracle_boundary_independently_rejects_distinct_unauthorized_functions(string sql)
    {
        var parsed = new LibPgQuerySqlParser().Parse(sql, CancellationToken.None);
        Assert.True(parsed.Success, parsed.RedactedMessage);
        SavException error = Assert.Throws<SavException>(() => OracleSqlBoundary.BuildWrappedCommand(
            OracleSqlTemplateKind.QuerySucceedsExists, parsed.Ir!, sql, ["sav_scope.sav_safe_fn"]));
        Assert.Equal(SavErrorCode.UnsupportedConstruct, error.Code);
    }

    [Theory]
    [InlineData("SELECT sav_scope.\"SAV_SAFE_FN\"()", "sav_scope.SAV_SAFE_FN")]
    [InlineData("SELECT \"SAV_SCOPE\".sav_safe_fn()", "SAV_SCOPE.sav_safe_fn")]
    public async Task Quoted_case_distinct_function_is_allowed_only_when_explicitly_authorized(string sql, string allowed)
    {
        using var root = CreatePolicyRoot();
        string path = Path.Combine(root.Path, root.PolicyRelativePath);
        File.WriteAllText(path, File.ReadAllText(path).Replace("sav_scope.sav_safe_fn", allowed, StringComparison.Ordinal));
        AnalyzeSqlResponse response = await CreateUseCase(root.Path).ExecuteAsync(
            new(sql, root.PolicyRelativePath, null), CancellationToken.None);
        Assert.Equal(PolicyOutcome.Allow, response.Decision.Outcome);
        Assert.Empty(response.Decision.RuleIds);

        var parsed = new LibPgQuerySqlParser().Parse(sql, CancellationToken.None);
        Assert.Contains(sql, OracleSqlBoundary.BuildWrappedCommand(
            OracleSqlTemplateKind.QuerySucceedsExists, parsed.Ir!, sql, [allowed]), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("SELECT sav_scope.\"SAV_SAFE_FN\"()", 1)] // F08
    [InlineData("SELECT \"SAV_SCOPE\".sav_safe_fn()", 1)] // R02
    [InlineData("SELECT sav_scope.sav_safe_fn(), sav_scope.\"SAV_SAFE_FN\"()", 2)] // R03
    [InlineData("SELECT sav_scope.\"SAV_SAFE_FN\"(), sav_scope.sav_safe_fn()", 2)]
    [InlineData("SELECT sav_scope.sav_safe_fn(), \"SAV_SCOPE\".sav_safe_fn()", 2)]
    [InlineData("SELECT sav_scope.\"SaV_Safe_Fn\"()", 1)]
    [InlineData("SELECT pg_catalog.\"LOWER\"('CANARY_LITERAL')", 1)]
    [InlineData("SELECT \"PG_CATALOG\".lower('CANARY_LITERAL')", 1)]
    [InlineData("SELECT sav_safe_fn()", 1)]
    [InlineData("SELECT sav_scope.lower('CANARY_LITERAL')", 1)]
    [InlineData("SELECT \"*\"()", 1)]
    [InlineData("SELECT \" \"()", 1)]
    public async Task Distinct_unauthorized_functions_are_denied_and_strictly_redacted(string sql, int count)
    {
        using var root = CreatePolicyRoot();
        AnalyzeSqlUseCase useCase = CreateUseCase(root.Path);
        AnalyzeSqlRequest request = new(sql, root.PolicyRelativePath, null);
        AnalyzeSqlResponse response = await useCase.ExecuteAsync(request, CancellationToken.None);

        Assert.True(response.Analysis.IsParsable);
        Assert.Equal(PolicyOutcome.Deny, response.Decision.Outcome);
        Assert.Equal(["unknown_function"], response.Decision.RuleIds);
        Assert.Equal(response.Decision.RuleIds, response.Decision.Reasons);
        Assert.Equal(response.Decision.Reasons, response.RedactedReasons);
        Assert.Equal(count, response.Analysis.Ir.Functions.Count);
        Assert.All(response.Analysis.Ir.Functions, name => Assert.Equal("[REDACTED]", name));
        string json = CanonicalJson.Serialize(response);
        Assert.DoesNotContain("sav_scope", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("CANARY_LITERAL", json);
        Assert.DoesNotContain("functionReferences", json);
        Assert.Equal(json, CanonicalJson.Serialize(await useCase.ExecuteAsync(request, CancellationToken.None)));

        var parsed = new LibPgQuerySqlParser().Parse(sql, CancellationToken.None);
        SavException error = Assert.Throws<SavException>(() => OracleSqlBoundary.BuildWrappedCommand(
            OracleSqlTemplateKind.QuerySucceedsExists, parsed.Ir!, sql, ["lower", "length", "sav_scope.sav_safe_fn"]));
        Assert.Equal(SavErrorCode.UnsupportedConstruct, error.Code);
    }

    [Theory]
    [InlineData("SELECT sav_scope.sav_safe_fn()")]
    [InlineData("SELECT SAV_SCOPE.SAV_SAFE_FN()")]
    [InlineData("SELECT \"sav_scope\".\"sav_safe_fn\"()")]
    [InlineData("SELECT PG_CATALOG.LOWER('x')")]
    [InlineData("SELECT \"pg_catalog\".\"lower\"('x')")]
    [InlineData("SELECT LOWER('x')")]
    public async Task Explicitly_authorized_normalized_functions_remain_allowed(string sql)
    {
        using var root = CreatePolicyRoot();
        AnalyzeSqlResponse response = await CreateUseCase(root.Path).ExecuteAsync(
            new(sql, root.PolicyRelativePath, null), CancellationToken.None);
        Assert.True(response.Analysis.IsParsable);
        Assert.Equal(PolicyOutcome.Allow, response.Decision.Outcome);
        Assert.Empty(response.Decision.RuleIds);

        var parsed = new LibPgQuerySqlParser().Parse(sql, CancellationToken.None);
        string wrapped = OracleSqlBoundary.BuildWrappedCommand(
            OracleSqlTemplateKind.QuerySucceedsExists, parsed.Ir!, sql, ["lower", "length", "sav_scope.sav_safe_fn"]);
        Assert.Contains(sql, wrapped, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("SELECT \"sav_scope.sav_safe_fn\"()")]
    [InlineData("SELECT \"pg_catalog.lower\"('x')")]
    public async Task Ambiguous_delimited_qualification_is_rejected_even_if_flattened_name_is_allowed(string sql)
    {
        using var root = CreatePolicyRoot();
        AnalyzeSqlResponse response = await CreateUseCase(root.Path).ExecuteAsync(
            new(sql, root.PolicyRelativePath, null), CancellationToken.None);
        Assert.Equal(PolicyOutcome.Deny, response.Decision.Outcome);
        Assert.Contains("unsupported_construct", response.Decision.RuleIds);
    }

    private static SecurityAnalyzeHarness.TempPolicyRoot CreatePolicyRoot()
    {
        var root = SecurityAnalyzeHarness.CreatePolicyRoot("valid-basic.yaml");
        string path = Path.Combine(root.Path, root.PolicyRelativePath);
        File.WriteAllText(path, File.ReadAllText(path)
            .Replace("allowedFunctions: []", "allowedFunctions: [lower, length, sav_scope.sav_safe_fn]", StringComparison.Ordinal)
            .Replace("denyUnresolvedObjects: true", "denyUnresolvedObjects: false", StringComparison.Ordinal));
        return root;
    }

    private static AnalyzeSqlUseCase CreateUseCase(string root) => new(
        new LibPgQuerySqlParser(), new YamlPolicyEngine(), new YamlPolicyLoader(), new YamlContractLoader(),
        new ConfigPathResolver(new ConfigRootOptions { ConfigRoot = root }), new StrictRedactor());
}
