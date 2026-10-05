using Microsoft.Extensions.DependencyInjection;
using Sav.Application.Abstractions;
using Sav.Application.Verify;
using Sav.Host.Mcp.Tools;

namespace Sav.Host.Tests.E2E;

/// <summary>
/// M009e: cancel mid verify_equivalence without row leakage (use case + MCP).
/// </summary>
public sealed class CancellationVerifyEquivalenceE2ETests : SavEnvTestBase
{
    [Fact]
    public async Task Verify_equivalence_use_case_honors_cancelled_token_without_row_leak()
    {
        using E2EHostHarness.TempWorkspace workspace = E2EHostHarness.CreateWorkspace();
        File.Copy(
            Path.Combine(E2EHostHarness.FindRepoRoot(), "tests", "fixtures", "contracts", "valid-mvp-b-equivalence.yaml"),
            Path.Combine(workspace.ConfigRoot, "contract.yaml"),
            overwrite: true);

        await using ServiceProvider sp = E2EHostHarness.BuildFull(workspace);
        IVerifyEquivalenceUseCase useCase = sp.GetRequiredService<IVerifyEquivalenceUseCase>();

        using CancellationTokenSource cts = new();
        cts.Cancel();

        OperationCanceledException ex = await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            useCase.ExecuteAsync(
                new VerifyEquivalenceRequest(
                    $"SELECT '{E2EHostHarness.CanaryLiteral}'",
                    "SELECT 1",
                    "missing_alias",
                    workspace.PolicyRelativePath,
                    workspace.ContractRelativePath),
                cts.Token));

        E2EHostHarness.AssertNoCanary(ex.ToString());
        Assert.Empty(Directory.EnumerateFiles(workspace.StoreRoot, "*", SearchOption.AllDirectories));
    }

    [Fact]
    public async Task Verify_equivalence_mcp_tool_honors_cancelled_token_without_row_leak()
    {
        using E2EHostHarness.TempWorkspace workspace = E2EHostHarness.CreateWorkspace();
        File.Copy(
            Path.Combine(E2EHostHarness.FindRepoRoot(), "tests", "fixtures", "contracts", "valid-mvp-b-equivalence.yaml"),
            Path.Combine(workspace.ConfigRoot, "contract.yaml"),
            overwrite: true);

        await using ServiceProvider sp = E2EHostHarness.BuildFull(workspace);
        VerifyEquivalenceTool tool = new(sp.GetRequiredService<IVerifyEquivalenceUseCase>());

        using CancellationTokenSource cts = new();
        cts.Cancel();

        OperationCanceledException ex = await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            tool.VerifyEquivalence(
                $"SELECT '{E2EHostHarness.CanaryLiteral}'",
                "SELECT 1",
                "missing_alias",
                workspace.PolicyRelativePath,
                workspace.ContractRelativePath,
                cts.Token));

        E2EHostHarness.AssertNoCanary(ex.ToString());
        Assert.Empty(Directory.EnumerateFiles(workspace.StoreRoot, "*", SearchOption.AllDirectories));
    }
}
