using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Sav.Application.Abstractions;
using Sav.Application.Analyze;
using Sav.Domain.Decisions;
using Sav.Host.Composition;
using Sav.Host.Mcp.Tools;

namespace Sav.Host.Tests.E2E;

public sealed class AnalyzeSqlE2ETests : SavEnvTestBase
{
    [Fact]
    public async Task Analyze_via_real_host_di_allows_select_one()
    {
        using E2EHostHarness.TempWorkspace workspace = E2EHostHarness.CreateWorkspace(includeContract: false);
        using ServiceProvider sp = E2EHostHarness.BuildAnalyzeOnly(workspace);
        IAnalyzeSqlUseCase useCase = sp.GetRequiredService<IAnalyzeSqlUseCase>();

        AnalyzeSqlResponse response = await useCase.ExecuteAsync(
            new AnalyzeSqlRequest("SELECT 1", workspace.PolicyRelativePath, null),
            CancellationToken.None);

        Assert.Equal(PolicyOutcome.Allow, response.Decision.Outcome);
        Assert.True(response.Analysis.IsParsable);
        Assert.False(response.EffectiveDisclosure.IncludeObjectNames);
    }

    [Fact]
    public async Task AnalyzeOnly_denies_select_into()
    {
        using E2EHostHarness.TempWorkspace workspace = E2EHostHarness.CreateWorkspace(includeContract: false);
        using ServiceProvider sp = E2EHostHarness.BuildAnalyzeOnly(workspace);
        IAnalyzeSqlUseCase useCase = sp.GetRequiredService<IAnalyzeSqlUseCase>();

        AnalyzeSqlResponse response = await useCase.ExecuteAsync(
            new AnalyzeSqlRequest(
                "SELECT id INTO archived_users FROM users",
                workspace.PolicyRelativePath,
                null),
            CancellationToken.None);

        Assert.Equal(PolicyOutcome.Deny, response.Decision.Outcome);
        Assert.Contains("unsupported_construct", response.Decision.RuleIds, StringComparer.Ordinal);
    }

    [Fact]
    public void Analyze_via_cli_writes_json_decision_to_stdout()
    {
        using E2EHostHarness.TempWorkspace workspace = E2EHostHarness.CreateWorkspace(includeContract: false);
        using IDisposable env = E2EHostHarness.ConfigureCliEnvironment(workspace, DiProfile.AnalyzeOnly);

        using StringWriter stdout = new();
        using StringWriter stderr = new();
        int exit = Program.Run(
            [
                "--mode", "AnalyzeOnly",
                "analyze",
                "--sql", "SELECT 1",
                "--policy", workspace.PolicyRelativePath,
            ],
            stdout,
            stderr);

        Assert.Equal(0, exit);
        Assert.True(string.IsNullOrWhiteSpace(stderr.ToString()));
        string json = stdout.ToString();
        Assert.Contains("\"outcome\"", json, StringComparison.OrdinalIgnoreCase);
        E2EHostHarness.AssertNoConnectionStringLeak(json);
        using JsonDocument doc = JsonDocument.Parse(json.Trim());
        Assert.Equal(
            (int)PolicyOutcome.Allow,
            doc.RootElement.GetProperty("decision").GetProperty("outcome").GetInt32());
    }

    [Fact]
    public async Task Analyze_via_mcp_tool_returns_canonical_json()
    {
        using E2EHostHarness.TempWorkspace workspace = E2EHostHarness.CreateWorkspace(includeContract: false);
        using ServiceProvider sp = E2EHostHarness.BuildAnalyzeOnly(workspace);
        AnalyzeSqlTool tool = new(sp.GetRequiredService<IAnalyzeSqlUseCase>());

        string json = await tool.AnalyzeSql(
            "SELECT 1",
            workspace.PolicyRelativePath,
            contractPath: null,
            CancellationToken.None);

        using JsonDocument doc = JsonDocument.Parse(json);
        Assert.Equal(
            (int)PolicyOutcome.Allow,
            doc.RootElement.GetProperty("decision").GetProperty("outcome").GetInt32());
        E2EHostHarness.AssertNoCanary(json);
        E2EHostHarness.AssertNoConnectionStringLeak(json);
    }

    [Fact]
    public async Task Analyze_deny_multi_statement_via_host_di()
    {
        using E2EHostHarness.TempWorkspace workspace = E2EHostHarness.CreateWorkspace(includeContract: false);
        using ServiceProvider sp = E2EHostHarness.BuildAnalyzeOnly(workspace);
        IAnalyzeSqlUseCase useCase = sp.GetRequiredService<IAnalyzeSqlUseCase>();

        AnalyzeSqlResponse response = await useCase.ExecuteAsync(
            new AnalyzeSqlRequest("SELECT 1; SELECT 2", workspace.PolicyRelativePath, null),
            CancellationToken.None);

        Assert.Equal(PolicyOutcome.Deny, response.Decision.Outcome);
    }
}
