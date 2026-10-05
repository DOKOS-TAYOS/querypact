using Microsoft.Extensions.DependencyInjection;
using Sav.Application.Abstractions;
using Sav.Application.Analyze;
using Sav.Host.Mcp.Tools;

namespace Sav.Host.Tests.E2E;

public sealed class CancellationAnalyzeE2ETests : SavEnvTestBase
{
    [Fact]
    public async Task Analyze_use_case_honors_cancelled_token()
    {
        using E2EHostHarness.TempWorkspace workspace = E2EHostHarness.CreateWorkspace(includeContract: false);
        using ServiceProvider sp = E2EHostHarness.BuildAnalyzeOnly(workspace);
        IAnalyzeSqlUseCase useCase = sp.GetRequiredService<IAnalyzeSqlUseCase>();

        using CancellationTokenSource cts = new();
        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            useCase.ExecuteAsync(
                new AnalyzeSqlRequest("SELECT 1", workspace.PolicyRelativePath, null),
                cts.Token));
    }

    [Fact]
    public async Task Analyze_mcp_tool_honors_cancelled_token()
    {
        using E2EHostHarness.TempWorkspace workspace = E2EHostHarness.CreateWorkspace(includeContract: false);
        using ServiceProvider sp = E2EHostHarness.BuildAnalyzeOnly(workspace);
        AnalyzeSqlTool tool = new(sp.GetRequiredService<IAnalyzeSqlUseCase>());

        using CancellationTokenSource cts = new();
        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            tool.AnalyzeSql("SELECT 1", workspace.PolicyRelativePath, null, cts.Token));
    }
}
