using Sav.Application.Analyze;
using Sav.Domain.Decisions;

namespace Sav.Security.Tests.Bypass;

public sealed class CteSubqueryAliasTests
{
    [Theory]
    [InlineData("bypass_cte_denied_table", "denied_table")]
    [InlineData("bypass_subquery_denied_table", "denied_table")]
    [InlineData("bypass_alias_denied_table", "denied_table")]
    public async Task Denied_table_cannot_bypass_via_cte_subquery_or_alias(string corpusId, string expectedRule)
    {
        using SecurityAnalyzeHarness.TempPolicyRoot root =
            SecurityAnalyzeHarness.CreatePolicyRoot("security-deny-secrets.yaml");
        AnalyzeSqlUseCase useCase = SecurityAnalyzeHarness.CreateUseCase(root.Path);

        AnalyzeSqlResponse response = await useCase.ExecuteAsync(
            new AnalyzeSqlRequest(SecurityAnalyzeHarness.CorpusSql(corpusId), root.PolicyRelativePath, null),
            CancellationToken.None);

        Assert.Equal(PolicyOutcome.Deny, response.Decision.Outcome);
        Assert.Contains(expectedRule, response.Decision.RuleIds);
        Assert.DoesNotContain("allow", response.Decision.Outcome.ToString(), StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("SELECT u FROM users AS u")]
    [InlineData("SELECT users FROM users")]
    [InlineData("SELECT u FROM public.users AS u")]
    [InlineData("SELECT ROW(u) FROM users u")]
    [InlineData("SELECT (u).ssn FROM users u")]
    [InlineData("SELECT q FROM (SELECT id FROM users) AS q")]
    [InlineData("WITH q AS (SELECT id FROM users) SELECT q FROM q")]
    [InlineData("SELECT j FROM users u JOIN accounts a USING (ssn) AS j")]
    [InlineData("SELECT u.id FROM users u NATURAL JOIN accounts a")]
    public async Task Whole_row_references_cannot_bypass_denied_column_policy(string sql)
    {
        using SecurityAnalyzeHarness.TempPolicyRoot root =
            SecurityAnalyzeHarness.CreatePolicyRoot("security-deny-secrets.yaml");
        string policyPath = Path.Combine(root.Path, root.PolicyRelativePath);
        File.WriteAllText(policyPath, File.ReadAllText(policyPath).Replace(
            "deniedColumns: []", "deniedColumns:\n  - ssn", StringComparison.Ordinal));

        AnalyzeSqlResponse response = await SecurityAnalyzeHarness.CreateUseCase(root.Path).ExecuteAsync(
            new AnalyzeSqlRequest(sql, root.PolicyRelativePath, null), CancellationToken.None);

        Assert.Equal(PolicyOutcome.Deny, response.Decision.Outcome);
        Assert.Contains("unsupported_construct", response.Decision.RuleIds);
    }

    [Fact]
    public async Task Join_using_cannot_read_denied_keys_without_projecting_them()
    {
        using SecurityAnalyzeHarness.TempPolicyRoot root =
            SecurityAnalyzeHarness.CreatePolicyRoot("security-deny-secrets.yaml");
        string policyPath = Path.Combine(root.Path, root.PolicyRelativePath);
        File.WriteAllText(policyPath, File.ReadAllText(policyPath).Replace(
            "deniedColumns: []", "deniedColumns:\n  - ssn", StringComparison.Ordinal));

        AnalyzeSqlResponse response = await SecurityAnalyzeHarness.CreateUseCase(root.Path).ExecuteAsync(
            new AnalyzeSqlRequest(
                "SELECT u.id FROM users u JOIN accounts a USING (ssn) AS j",
                root.PolicyRelativePath, null), CancellationToken.None);

        Assert.Equal(PolicyOutcome.Deny, response.Decision.Outcome);
        Assert.Contains("denied_column", response.Decision.RuleIds);
    }

    [Theory]
    [InlineData("SELECT u.email FROM users AS u")]
    [InlineData("SELECT email FROM users AS u")]
    [InlineData("SELECT u.id FROM public.users AS u")]
    [InlineData("WITH q AS (SELECT email FROM users) SELECT email FROM q")]
    public async Task Individual_column_references_remain_accepted_under_denied_column_policy(string sql)
    {
        using SecurityAnalyzeHarness.TempPolicyRoot root =
            SecurityAnalyzeHarness.CreatePolicyRoot("security-deny-secrets.yaml");
        string policyPath = Path.Combine(root.Path, root.PolicyRelativePath);
        File.WriteAllText(policyPath, File.ReadAllText(policyPath).Replace(
            "deniedColumns: []", "deniedColumns:\n  - ssn", StringComparison.Ordinal));

        AnalyzeSqlResponse response = await SecurityAnalyzeHarness.CreateUseCase(root.Path).ExecuteAsync(
            new AnalyzeSqlRequest(sql, root.PolicyRelativePath, null), CancellationToken.None);

        Assert.Equal(PolicyOutcome.Allow, response.Decision.Outcome);
    }

    [Fact]
    public async Task Unknown_function_is_denied_when_allow_list_is_set()
    {
        using SecurityAnalyzeHarness.TempPolicyRoot root =
            SecurityAnalyzeHarness.CreatePolicyRoot("security-deny-secrets.yaml");
        AnalyzeSqlUseCase useCase = SecurityAnalyzeHarness.CreateUseCase(root.Path);

        AnalyzeSqlResponse response = await useCase.ExecuteAsync(
            new AnalyzeSqlRequest(
                SecurityAnalyzeHarness.CorpusSql("bypass_function_unknown"),
                root.PolicyRelativePath,
                null),
            CancellationToken.None);

        Assert.Equal(PolicyOutcome.Deny, response.Decision.Outcome);
        Assert.Contains("unknown_function", response.Decision.RuleIds);
    }

    [Fact]
    public async Task Pg_catalog_qualified_allowed_function_is_not_split_or_denied()
    {
        using SecurityAnalyzeHarness.TempPolicyRoot root =
            SecurityAnalyzeHarness.CreatePolicyRoot("security-deny-secrets.yaml");
        AnalyzeSqlUseCase useCase = SecurityAnalyzeHarness.CreateUseCase(root.Path);

        AnalyzeSqlResponse response = await useCase.ExecuteAsync(
            new AnalyzeSqlRequest(
                "SELECT pg_catalog.lower(email) FROM users",
                root.PolicyRelativePath,
                null),
            CancellationToken.None);

        Assert.Equal(PolicyOutcome.Allow, response.Decision.Outcome);
        Assert.DoesNotContain("unknown_function", response.Decision.RuleIds);
    }

    [Fact]
    public async Task Non_pg_catalog_qualified_function_does_not_bypass_unqualified_allow_list()
    {
        using SecurityAnalyzeHarness.TempPolicyRoot root =
            SecurityAnalyzeHarness.CreatePolicyRoot("security-deny-secrets.yaml");
        AnalyzeSqlUseCase useCase = SecurityAnalyzeHarness.CreateUseCase(root.Path);

        AnalyzeSqlResponse response = await useCase.ExecuteAsync(
            new AnalyzeSqlRequest(
                "SELECT private.lower(email) FROM users",
                root.PolicyRelativePath,
                null),
            CancellationToken.None);

        Assert.Equal(PolicyOutcome.Deny, response.Decision.Outcome);
        Assert.Contains("unknown_function", response.Decision.RuleIds);
    }

    [Fact]
    public async Task Quoted_noncanonical_pg_catalog_schema_does_not_bypass_allow_list()
    {
        using SecurityAnalyzeHarness.TempPolicyRoot root =
            SecurityAnalyzeHarness.CreatePolicyRoot("security-deny-secrets.yaml");
        AnalyzeSqlUseCase useCase = SecurityAnalyzeHarness.CreateUseCase(root.Path);

        AnalyzeSqlResponse response = await useCase.ExecuteAsync(
            new AnalyzeSqlRequest(
                "SELECT \"PG_CATALOG\".lower(email) FROM users",
                root.PolicyRelativePath,
                null),
            CancellationToken.None);

        Assert.Equal(PolicyOutcome.Deny, response.Decision.Outcome);
        Assert.Contains("unknown_function", response.Decision.RuleIds);
    }

    [Fact]
    public async Task Write_insert_is_denied_when_only_select_allowed()
    {
        using SecurityAnalyzeHarness.TempPolicyRoot root =
            SecurityAnalyzeHarness.CreatePolicyRoot("security-deny-secrets.yaml");
        AnalyzeSqlUseCase useCase = SecurityAnalyzeHarness.CreateUseCase(root.Path);

        AnalyzeSqlResponse response = await useCase.ExecuteAsync(
            new AnalyzeSqlRequest(
                SecurityAnalyzeHarness.CorpusSql("bypass_write_insert"),
                root.PolicyRelativePath,
                null),
            CancellationToken.None);

        Assert.Equal(PolicyOutcome.Deny, response.Decision.Outcome);
        Assert.Contains("forbidden_statement_type", response.Decision.RuleIds);
    }

    [Fact]
    public async Task Multi_statement_is_denied()
    {
        using SecurityAnalyzeHarness.TempPolicyRoot root =
            SecurityAnalyzeHarness.CreatePolicyRoot("security-deny-secrets.yaml");
        AnalyzeSqlUseCase useCase = SecurityAnalyzeHarness.CreateUseCase(root.Path);

        AnalyzeSqlResponse response = await useCase.ExecuteAsync(
            new AnalyzeSqlRequest(
                SecurityAnalyzeHarness.CorpusSql("bypass_multi_statement"),
                root.PolicyRelativePath,
                null),
            CancellationToken.None);

        Assert.Equal(PolicyOutcome.Deny, response.Decision.Outcome);
        Assert.Contains("multiple_statements", response.Decision.RuleIds);
    }

    [Fact]
    public void Differential_seed_fixture_has_at_least_five_cases()
    {
        string path = Path.Combine(
            SecurityAnalyzeHarness.FindRepoRoot(),
            "tests",
            "fixtures",
            "sql",
            "parser-catalog-differential-seeds.json");
        using FileStream stream = File.OpenRead(path);
        using System.Text.Json.JsonDocument doc = System.Text.Json.JsonDocument.Parse(stream);
        HashSet<string> ids = new(StringComparer.Ordinal);
        foreach (System.Text.Json.JsonElement item in doc.RootElement.GetProperty("cases").EnumerateArray())
        {
            string? id = item.GetProperty("id").GetString();
            Assert.False(string.IsNullOrWhiteSpace(id));
            Assert.True(ids.Add(id!), "duplicate differential seed id: " + id);
            Assert.True(item.TryGetProperty("parserClaims", out _));
            Assert.True(item.TryGetProperty("catalogOutcome", out _));
        }

        Assert.True(ids.Count >= 5, $"expected ≥5 differential seeds, got {ids.Count}");
    }
}
