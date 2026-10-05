using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Sav.Application.Abstractions;
using Sav.Application.Verify;
using Sav.Domain.Decisions;
using Sav.Domain.Serialization;
using Sav.Host.Composition;
using Sav.Host.Mcp.Tools;
using Sav.Infrastructure.Postgres.Tests.Fixtures;

namespace Sav.Host.Tests.E2E;

public sealed class VerifyQueryE2ETests : SavEnvTestBase
{
    [Fact]
    public async Task Verify_query_deny_unknown_alias_persists_attestation_without_docker()
    {
        using E2EHostHarness.TempWorkspace workspace = E2EHostHarness.CreateWorkspace();
        await using ServiceProvider sp = E2EHostHarness.BuildFull(workspace);
        IVerifyQueryUseCase useCase = sp.GetRequiredService<IVerifyQueryUseCase>();

        VerifyQueryResponse response = await useCase.ExecuteAsync(
            new VerifyQueryRequest(
                "SELECT 1",
                "no_such_alias",
                workspace.PolicyRelativePath,
                workspace.ContractRelativePath),
            CancellationToken.None);

        Assert.Equal(AttestationDecision.Deny, response.Attestation.Decision);
        Assert.False(string.IsNullOrWhiteSpace(response.AttestationId));
        Assert.Equal(response.AttestationId, response.Attestation.Id);
    }

    [Fact]
    public void Verify_query_cli_deny_path_writes_attestation_json()
    {
        using E2EHostHarness.TempWorkspace workspace = E2EHostHarness.CreateWorkspace();
        using IDisposable env = E2EHostHarness.ConfigureCliEnvironment(workspace, DiProfile.Full);

        using StringWriter stdout = new();
        using StringWriter stderr = new();
        int exit = Program.Run(
            [
                "--mode", "Full",
                "verify-query",
                "--sql", $"SELECT '{E2EHostHarness.CanaryLiteral}'",
                "--target", "no_such_alias",
                "--policy", workspace.PolicyRelativePath,
                "--contract", workspace.ContractRelativePath,
            ],
            stdout,
            stderr);

        Assert.Equal(0, exit);
        string json = stdout.ToString();
        Assert.Contains("attestationId", json, StringComparison.OrdinalIgnoreCase);
        using JsonDocument doc = JsonDocument.Parse(json.Trim());
        Assert.Equal(
            (int)AttestationDecision.Deny,
            doc.RootElement.GetProperty("attestation").GetProperty("decision").GetInt32());
        E2EHostHarness.AssertNoCanary(json);
        E2EHostHarness.AssertNoConnectionStringLeak(json);
        E2EHostHarness.AssertNoConnectionStringLeak(stderr.ToString());
    }

    [Fact]
    public async Task Verify_query_mcp_tool_deny_path_returns_attestation_json()
    {
        using E2EHostHarness.TempWorkspace workspace = E2EHostHarness.CreateWorkspace();
        await using ServiceProvider sp = E2EHostHarness.BuildFull(workspace);
        VerifyQueryTool tool = new(sp.GetRequiredService<IVerifyQueryUseCase>());

        string json = await tool.VerifyQuery(
            $"SELECT '{E2EHostHarness.CanaryLiteral}'",
            "no_such_alias",
            workspace.PolicyRelativePath,
            workspace.ContractRelativePath,
            CancellationToken.None);

        using JsonDocument doc = JsonDocument.Parse(json);
        Assert.False(string.IsNullOrWhiteSpace(doc.RootElement.GetProperty("attestationId").GetString()));
        Assert.Equal(
            (int)AttestationDecision.Deny,
            doc.RootElement.GetProperty("attestation").GetProperty("decision").GetInt32());
        E2EHostHarness.AssertNoCanary(json);
    }
}

[Collection(nameof(PostgresRoCollection))]
public sealed class VerifyQueryDockerE2ETests : SavEnvTestBase
{
    private readonly PostgresRoFixture _fixture;

    public VerifyQueryDockerE2ETests(PostgresRoFixture fixture)
    {
        _fixture = fixture;
    }

    [Fact]
    public async Task Verify_query_allow_path_with_postgres_via_real_host_di()
    {
        string dsnEnv = _fixture.Binding.AliasToDsnEnvVar[PostgresRoFixture.RoAlias];
        using E2EHostHarness.TempWorkspace workspace = E2EHostHarness.CreateWorkspace(
            aliasToDsnEnvVar: new Dictionary<string, string>
            {
                [PostgresRoFixture.RoAlias] = dsnEnv,
            });

        await using ServiceProvider sp = E2EHostHarness.BuildFull(workspace);
        IVerifyQueryUseCase useCase = sp.GetRequiredService<IVerifyQueryUseCase>();

        // empty_result fails on SELECT 1 (one row): still a completed verify path with attestation.
        VerifyQueryResponse response = await useCase.ExecuteAsync(
            new VerifyQueryRequest(
                "SELECT 1",
                PostgresRoFixture.RoAlias,
                workspace.PolicyRelativePath,
                workspace.ContractRelativePath),
            CancellationToken.None);

        Assert.False(string.IsNullOrWhiteSpace(response.AttestationId));
        Assert.NotEqual(AttestationDecision.Deny, response.Attestation.Decision);
        Assert.Contains(response.Attestation.Properties, p => p.Name == "query_succeeds");
        Assert.Contains(response.Attestation.Properties, p => p.Name == "empty_result");
        E2EHostHarness.AssertNoConnectionStringLeak(CanonicalJson.Serialize(response));
    }

    [Fact]
    public async Task Verify_query_resolvable_relation_with_deny_unresolved_policy_reaches_oracle()
    {
        string dsnEnv = _fixture.Binding.AliasToDsnEnvVar[PostgresRoFixture.RoAlias];
        using E2EHostHarness.TempWorkspace workspace = E2EHostHarness.CreateWorkspace(
            aliasToDsnEnvVar: new Dictionary<string, string>
            {
                [PostgresRoFixture.RoAlias] = dsnEnv,
            });

        await using ServiceProvider sp = E2EHostHarness.BuildFull(workspace);
        IVerifyQueryUseCase useCase = sp.GetRequiredService<IVerifyQueryUseCase>();

        VerifyQueryResponse response = await useCase.ExecuteAsync(
            new VerifyQueryRequest(
                "SELECT id FROM public.plan_items",
                PostgresRoFixture.RoAlias,
                workspace.PolicyRelativePath,
                workspace.ContractRelativePath),
            CancellationToken.None);

        Assert.NotEqual(AttestationDecision.Deny, response.Attestation.Decision);
        Assert.Contains(response.Attestation.Properties, p => p.Name == "query_succeeds");
        Assert.Contains(response.Attestation.Properties, p => p.Name == "empty_result");
        E2EHostHarness.AssertNoConnectionStringLeak(CanonicalJson.Serialize(response));
    }
}
