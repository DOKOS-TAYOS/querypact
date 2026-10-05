using Microsoft.Extensions.DependencyInjection;
using Sav.Application.Abstractions;
using Sav.Application.Verify;
using Sav.Host.Mcp.Tools;

namespace Sav.Host.Tests.E2E;

public sealed class CancellationGetAttestationE2ETests : SavEnvTestBase
{
    [Fact]
    public async Task Get_attestation_use_case_honors_cancelled_token()
    {
        using E2EHostHarness.TempWorkspace workspace = E2EHostHarness.CreateWorkspace();
        await using ServiceProvider sp = E2EHostHarness.BuildFull(workspace);
        IVerifyQueryUseCase verify = sp.GetRequiredService<IVerifyQueryUseCase>();
        IGetAttestationUseCase get = sp.GetRequiredService<IGetAttestationUseCase>();

        VerifyQueryResponse created = await verify.ExecuteAsync(
            new VerifyQueryRequest(
                "NOT VALID SQL !!!",
                "missing_alias",
                workspace.PolicyRelativePath,
                workspace.ContractRelativePath),
            CancellationToken.None);

        using CancellationTokenSource cts = new();
        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            get.ExecuteAsync(created.AttestationId, cts.Token));
    }

    [Fact]
    public async Task Get_attestation_mcp_tool_honors_cancelled_token()
    {
        using E2EHostHarness.TempWorkspace workspace = E2EHostHarness.CreateWorkspace();
        await using ServiceProvider sp = E2EHostHarness.BuildFull(workspace);
        GetAttestationTool tool = new(sp.GetRequiredService<IGetAttestationUseCase>());

        using CancellationTokenSource cts = new();
        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            tool.GetAttestation(Guid.NewGuid().ToString("D"), cts.Token));
    }
}
