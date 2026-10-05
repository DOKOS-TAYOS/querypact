using Sav.Application.Analyze;
using Sav.Domain.Decisions;

namespace Sav.Security.Tests.Authorize;

public sealed class AnalyzeDenyUnresolvedWithoutCatalogTests
{
    [Fact]
    public async Task Analyze_denies_when_deny_unresolved_objects_and_no_catalog()
    {
        using SecurityAnalyzeHarness.TempPolicyRoot root =
            SecurityAnalyzeHarness.CreatePolicyRoot("security-deny-unresolved.yaml");
        AnalyzeSqlUseCase useCase = SecurityAnalyzeHarness.CreateUseCase(root.Path);

        AnalyzeSqlResponse response = await useCase.ExecuteAsync(
            new AnalyzeSqlRequest(
                "SELECT id FROM users WHERE active = true",
                root.PolicyRelativePath,
                null),
            CancellationToken.None);

        Assert.Equal(PolicyOutcome.Deny, response.Decision.Outcome);
        Assert.NotEqual(PolicyOutcome.Allow, response.Decision.Outcome);
        Assert.Contains("unresolved_object", response.Decision.RuleIds);
        Assert.NotEmpty(response.Analysis.Ir.UnresolvedObjects);
    }

    [Fact]
    public async Task Analyze_denies_cte_base_tables_as_unresolved_without_catalog()
    {
        using SecurityAnalyzeHarness.TempPolicyRoot root =
            SecurityAnalyzeHarness.CreatePolicyRoot("security-deny-unresolved.yaml");
        AnalyzeSqlUseCase useCase = SecurityAnalyzeHarness.CreateUseCase(root.Path);

        AnalyzeSqlResponse response = await useCase.ExecuteAsync(
            new AnalyzeSqlRequest(
                SecurityAnalyzeHarness.CorpusSql("cte"),
                root.PolicyRelativePath,
                null),
            CancellationToken.None);

        Assert.Equal(PolicyOutcome.Deny, response.Decision.Outcome);
        Assert.Contains("unresolved_object", response.Decision.RuleIds);
        Assert.Contains("users", response.Analysis.Ir.UnresolvedObjects, StringComparer.OrdinalIgnoreCase);
        Assert.Contains("orders", response.Analysis.Ir.UnresolvedObjects, StringComparer.OrdinalIgnoreCase);
        Assert.DoesNotContain("active_users", response.Analysis.Ir.UnresolvedObjects, StringComparer.OrdinalIgnoreCase);
    }
}
