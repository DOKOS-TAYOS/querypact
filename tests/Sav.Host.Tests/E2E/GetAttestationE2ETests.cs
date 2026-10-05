using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Sav.Application.Abstractions;
using Sav.Application.Verify;
using Sav.Domain.Attestations;
using Sav.Domain.Decisions;
using Sav.Host.Composition;
using Sav.Host.Mcp.Tools;

namespace Sav.Host.Tests.E2E;

public sealed class GetAttestationE2ETests : SavEnvTestBase
{
    [Fact]
    public async Task Get_attestation_roundtrip_via_host_di_after_verify_deny()
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

        Assert.False(string.IsNullOrWhiteSpace(created.AttestationId));
        Assert.Equal(AttestationDecision.Deny, created.Attestation.Decision);

        Attestation? loaded = await get.ExecuteAsync(created.AttestationId, CancellationToken.None);
        Assert.NotNull(loaded);
        Assert.Equal(created.AttestationId, loaded.Id);
        Assert.Equal(created.Attestation.HmacSha256Base64, loaded.HmacSha256Base64);
        Assert.Equal(AttestationDecision.Deny, loaded.Decision);
    }

    [Fact]
    public async Task Get_attestation_via_cli_after_verify_deny()
    {
        using E2EHostHarness.TempWorkspace workspace = E2EHostHarness.CreateWorkspace();
        using IDisposable env = E2EHostHarness.ConfigureCliEnvironment(workspace, DiProfile.Full);

        using StringWriter verifyOut = new();
        using StringWriter verifyErr = new();
        int verifyExit = Program.Run(
            [
                "--mode", "Full",
                "verify-query",
                "--sql", "NOT VALID SQL !!!",
                "--target", "missing_alias",
                "--policy", workspace.PolicyRelativePath,
                "--contract", workspace.ContractRelativePath,
            ],
            verifyOut,
            verifyErr);

        Assert.Equal(0, verifyExit);
        using JsonDocument verifyDoc = JsonDocument.Parse(verifyOut.ToString().Trim());
        string id = verifyDoc.RootElement.GetProperty("attestationId").GetString()
            ?? throw new InvalidOperationException("Missing attestationId.");

        using StringWriter getOut = new();
        using StringWriter getErr = new();
        int getExit = Program.Run(
            ["--mode", "Full", "attestation", "get", "--id", id],
            getOut,
            getErr);

        Assert.Equal(0, getExit);
        Assert.True(string.IsNullOrWhiteSpace(getErr.ToString()));
        string json = getOut.ToString();
        Assert.Contains(id, json, StringComparison.Ordinal);
        using JsonDocument getDoc = JsonDocument.Parse(json.Trim());
        Assert.Equal((int)AttestationDecision.Deny, getDoc.RootElement.GetProperty("decision").GetInt32());
        E2EHostHarness.AssertNoConnectionStringLeak(json);
        E2EHostHarness.AssertNoCanary(json);
    }

    [Fact]
    public async Task Get_attestation_via_mcp_tool()
    {
        using E2EHostHarness.TempWorkspace workspace = E2EHostHarness.CreateWorkspace();
        await using ServiceProvider sp = E2EHostHarness.BuildFull(workspace);
        IVerifyQueryUseCase verify = sp.GetRequiredService<IVerifyQueryUseCase>();
        GetAttestationTool tool = new(sp.GetRequiredService<IGetAttestationUseCase>());

        VerifyQueryResponse created = await verify.ExecuteAsync(
            new VerifyQueryRequest(
                "NOT VALID SQL !!!",
                "missing_alias",
                workspace.PolicyRelativePath,
                workspace.ContractRelativePath),
            CancellationToken.None);

        string json = await tool.GetAttestation(created.AttestationId, CancellationToken.None);
        using JsonDocument doc = JsonDocument.Parse(json);
        Assert.Equal(created.AttestationId, doc.RootElement.GetProperty("id").GetString());
        Assert.Equal((int)AttestationDecision.Deny, doc.RootElement.GetProperty("decision").GetInt32());
        E2EHostHarness.AssertNoCanary(json);
    }

    [Fact]
    public async Task Get_attestation_missing_id_returns_null_via_use_case()
    {
        using E2EHostHarness.TempWorkspace workspace = E2EHostHarness.CreateWorkspace();
        await using ServiceProvider sp = E2EHostHarness.BuildFull(workspace);
        IGetAttestationUseCase get = sp.GetRequiredService<IGetAttestationUseCase>();

        Attestation? loaded = await get.ExecuteAsync(Guid.NewGuid().ToString("D"), CancellationToken.None);
        Assert.Null(loaded);
    }
}
