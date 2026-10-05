using System.Text.Json;
using Sav.Application.Analyze;
using Sav.Domain.Decisions;

namespace Sav.Security.Tests.NoLeak;

public sealed class AnalyzeNormalizedSqlCanaryTests
{
    private const string Canary = "CANARY_LITERAL_do_not_egress@example.invalid";

    [Fact]
    public async Task Serialized_analyze_response_does_not_contain_agent_sql_literal()
    {
        using SecurityAnalyzeHarness.TempPolicyRoot root =
            SecurityAnalyzeHarness.CreatePolicyRoot("security-deny-unresolved.yaml");
        AnalyzeSqlUseCase useCase = SecurityAnalyzeHarness.CreateUseCase(root.Path);
        string sql = SecurityAnalyzeHarness.CorpusSql("canary_literal");
        Assert.Contains(Canary, sql, StringComparison.Ordinal);

        AnalyzeSqlResponse response = await useCase.ExecuteAsync(
            new AnalyzeSqlRequest(sql, root.PolicyRelativePath, null),
            CancellationToken.None);

        string json = JsonSerializer.Serialize(response);
        Assert.DoesNotContain(Canary, json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("NormalizedSql", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(sql, json, StringComparison.Ordinal);
        Assert.Null(response.Analysis.Ir.GetType().GetProperty("NormalizedSql"));
    }

    [Fact]
    public async Task Deny_reasons_do_not_echo_canary_literal()
    {
        using SecurityAnalyzeHarness.TempPolicyRoot root =
            SecurityAnalyzeHarness.CreatePolicyRoot("security-deny-secrets.yaml");
        AnalyzeSqlUseCase useCase = SecurityAnalyzeHarness.CreateUseCase(root.Path);

        AnalyzeSqlResponse response = await useCase.ExecuteAsync(
            new AnalyzeSqlRequest(
                "SELECT id FROM secrets WHERE note = '" + Canary + "'",
                root.PolicyRelativePath,
                null),
            CancellationToken.None);

        Assert.Equal(PolicyOutcome.Deny, response.Decision.Outcome);
        string json = JsonSerializer.Serialize(response);
        Assert.DoesNotContain(Canary, json, StringComparison.OrdinalIgnoreCase);
        Assert.All(response.RedactedReasons, r => Assert.DoesNotContain(Canary, r, StringComparison.OrdinalIgnoreCase));
        Assert.All(response.Decision.Reasons, r => Assert.DoesNotContain(Canary, r, StringComparison.OrdinalIgnoreCase));
    }
}
