using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Sav.Application.Abstractions;
using Sav.Domain.Errors;
using Sav.Host.Mcp.Tools;
using Sav.Host.Tests.E2E;

namespace Sav.Host.Tests;

/// <summary>
/// MCP PolicyPath / ContractPath confused-deputy / LFI (M009b1 gap closed for M010a-A-corpus-w1).
/// </summary>
public sealed class McpPathTraversalTests : SavEnvTestBase
{
    [Theory]
    [InlineData("../outside.yaml")]
    [InlineData("..\\outside.yaml")]
    [InlineData("/etc/passwd")]
    public async Task Analyze_sql_rejects_policy_path_escape(string escapePath)
    {
        using E2EHostHarness.TempWorkspace workspace = E2EHostHarness.CreateWorkspace(includeContract: false);
        using ServiceProvider sp = E2EHostHarness.BuildAnalyzeOnly(workspace);
        AnalyzeSqlTool tool = new(sp.GetRequiredService<IAnalyzeSqlUseCase>());

        string json = await tool.AnalyzeSql(
            "SELECT 1",
            escapePath,
            contractPath: null,
            CancellationToken.None);

        using JsonDocument doc = JsonDocument.Parse(json);
        Assert.Equal(SavErrorCode.PathNotAllowed, doc.RootElement.GetProperty("error").GetString());
        E2EHostHarness.AssertNoConnectionStringLeak(json);
        Assert.DoesNotContain(workspace.ConfigRoot, json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("outside.yaml", json, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Analyze_sql_rejects_contract_path_escape()
    {
        using E2EHostHarness.TempWorkspace workspace = E2EHostHarness.CreateWorkspace(includeContract: false);
        using ServiceProvider sp = E2EHostHarness.BuildAnalyzeOnly(workspace);
        AnalyzeSqlTool tool = new(sp.GetRequiredService<IAnalyzeSqlUseCase>());

        string json = await tool.AnalyzeSql(
            "SELECT 1",
            workspace.PolicyRelativePath,
            contractPath: "../outside-contract.yaml",
            CancellationToken.None);

        using JsonDocument doc = JsonDocument.Parse(json);
        Assert.Equal(SavErrorCode.PathNotAllowed, doc.RootElement.GetProperty("error").GetString());
        Assert.DoesNotContain("outside-contract", json, StringComparison.OrdinalIgnoreCase);
    }
}
