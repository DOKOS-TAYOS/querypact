using Microsoft.Extensions.DependencyInjection;
using Sav.Application.Abstractions;
using Sav.Application.Verify;
using Sav.Host.Mcp.Tools;

namespace Sav.Host.Tests.E2E;

public sealed class CancellationVerifyQueryE2ETests : SavEnvTestBase
{
    [Fact]
    public async Task Verify_query_use_case_honors_cancelled_token()
    {
        using E2EHostHarness.TempWorkspace workspace = E2EHostHarness.CreateWorkspace();
        await using ServiceProvider sp = E2EHostHarness.BuildFull(workspace);
        IVerifyQueryUseCase useCase = sp.GetRequiredService<IVerifyQueryUseCase>();

        using CancellationTokenSource cts = new();
        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            useCase.ExecuteAsync(
                new VerifyQueryRequest(
                    "SELECT 1",
                    "missing_alias",
                    workspace.PolicyRelativePath,
                    workspace.ContractRelativePath),
                cts.Token));
    }

    [Fact]
    public async Task Verify_query_mcp_tool_honors_cancelled_token()
    {
        using E2EHostHarness.TempWorkspace workspace = E2EHostHarness.CreateWorkspace();
        await using ServiceProvider sp = E2EHostHarness.BuildFull(workspace);
        VerifyQueryTool tool = new(sp.GetRequiredService<IVerifyQueryUseCase>());

        using CancellationTokenSource cts = new();
        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            tool.VerifyQuery(
                "SELECT 1",
                "missing_alias",
                workspace.PolicyRelativePath,
                workspace.ContractRelativePath,
                cts.Token));
    }
}
