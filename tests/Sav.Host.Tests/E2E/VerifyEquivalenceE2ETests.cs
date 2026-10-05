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

/// <summary>
/// M009e: E2E verify_equivalence against real host DI (+ Docker for allow path).
/// </summary>
public sealed class VerifyEquivalenceE2ETests : SavEnvTestBase
{
    [Fact]
    public async Task Verify_equivalence_deny_unknown_alias_persists_attestation_without_docker()
    {
        using E2EHostHarness.TempWorkspace workspace = CreateEquivalenceWorkspace();
        await using ServiceProvider sp = E2EHostHarness.BuildFull(workspace);
        IVerifyEquivalenceUseCase useCase = sp.GetRequiredService<IVerifyEquivalenceUseCase>();

        VerifyEquivalenceResponse response = await useCase.ExecuteAsync(
            new VerifyEquivalenceRequest(
                "SELECT 1",
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
    public void Verify_equivalence_cli_deny_path_writes_attestation_json()
    {
        using E2EHostHarness.TempWorkspace workspace = CreateEquivalenceWorkspace();
        using IDisposable env = E2EHostHarness.ConfigureCliEnvironment(workspace, DiProfile.Full);

        using StringWriter stdout = new();
        using StringWriter stderr = new();
        int exit = Program.Run(
            [
                "--mode", "Full",
                "verify-equivalence",
                "--left-sql", $"SELECT '{E2EHostHarness.CanaryLiteral}'",
                "--right-sql", "SELECT 1",
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
    public async Task Verify_equivalence_mcp_tool_deny_path_returns_attestation_json()
    {
        using E2EHostHarness.TempWorkspace workspace = CreateEquivalenceWorkspace();
        await using ServiceProvider sp = E2EHostHarness.BuildFull(workspace);
        VerifyEquivalenceTool tool = new(sp.GetRequiredService<IVerifyEquivalenceUseCase>());

        string json = await tool.VerifyEquivalence(
            $"SELECT '{E2EHostHarness.CanaryLiteral}'",
            "SELECT 1",
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

    private static E2EHostHarness.TempWorkspace CreateEquivalenceWorkspace(
        IReadOnlyDictionary<string, string>? aliasToDsnEnvVar = null)
    {
        E2EHostHarness.TempWorkspace workspace = E2EHostHarness.CreateWorkspace(
            aliasToDsnEnvVar: aliasToDsnEnvVar);
        string fixtures = Path.Combine(E2EHostHarness.FindRepoRoot(), "tests", "fixtures");
        File.Copy(
            Path.Combine(fixtures, "contracts", "valid-mvp-b-equivalence.yaml"),
            Path.Combine(workspace.ConfigRoot, "contract.yaml"),
            overwrite: true);
        return workspace;
    }
}

[Collection(nameof(PostgresRoCollection))]
public sealed class VerifyEquivalenceDockerE2ETests : SavEnvTestBase
{
    private readonly PostgresRoFixture _fixture;

    public VerifyEquivalenceDockerE2ETests(PostgresRoFixture fixture)
    {
        _fixture = fixture;
    }

    [Fact]
    public async Task Verify_equivalence_allow_path_with_postgres_via_real_host_di()
    {
        string dsnEnv = _fixture.Binding.AliasToDsnEnvVar[PostgresRoFixture.RoAlias];
        using E2EHostHarness.TempWorkspace workspace = E2EHostHarness.CreateWorkspace(
            aliasToDsnEnvVar: new Dictionary<string, string>
            {
                [PostgresRoFixture.RoAlias] = dsnEnv,
            });
        File.Copy(
            Path.Combine(E2EHostHarness.FindRepoRoot(), "tests", "fixtures", "contracts", "valid-mvp-b-equivalence.yaml"),
            Path.Combine(workspace.ConfigRoot, "contract.yaml"),
            overwrite: true);

        await using ServiceProvider sp = E2EHostHarness.BuildFull(workspace);
        IVerifyEquivalenceUseCase useCase = sp.GetRequiredService<IVerifyEquivalenceUseCase>();

        // SELECT 1 has no unresolved relations under denyUnresolvedObjects: still opens RO session + oracle.
        VerifyEquivalenceResponse response = await useCase.ExecuteAsync(
            new VerifyEquivalenceRequest(
                "SELECT 1",
                "SELECT 1",
                PostgresRoFixture.RoAlias,
                workspace.PolicyRelativePath,
                workspace.ContractRelativePath),
            CancellationToken.None);

        Assert.False(string.IsNullOrWhiteSpace(response.AttestationId));
        Assert.Equal(AttestationDecision.Pass, response.Attestation.Decision);
        Assert.Contains(response.Attestation.Properties, p => p.Name == "query_equivalent");
        E2EHostHarness.AssertNoConnectionStringLeak(CanonicalJson.Serialize(response));
    }
}
