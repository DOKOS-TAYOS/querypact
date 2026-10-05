using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Sav.Application.Abstractions;
using Sav.Application.Migrations;
using Sav.Domain.Decisions;
using Sav.Domain.Serialization;
using Sav.Host.Composition;
using Sav.Host.Mcp.Tools;

namespace Sav.Host.Tests.E2E;

/// <summary>
/// M009e: E2E verify_migration against real host DI. Allow path exercises Docker via
/// <c>ShadowMigrationRunner</c> (ephemeral Testcontainers).
/// </summary>
public sealed class VerifyMigrationE2ETests : SavEnvTestBase
{
    [Fact]
    public async Task Verify_migration_deny_path_never_needs_docker_and_attests()
    {
        using MigrationWorkspace workspace = MigrationWorkspace.Create();
        await using ServiceProvider sp = E2EHostHarness.BuildFull(workspace.AsTemp());
        IVerifyMigrationUseCase useCase = sp.GetRequiredService<IVerifyMigrationUseCase>();

        string deniedSql = File.ReadAllText(
            Path.Combine(E2EHostHarness.FindRepoRoot(), "tests", "fixtures", "migrations", "denied", "copy.sql"));

        VerifyMigrationResponse response = await useCase.ExecuteAsync(
            new VerifyMigrationRequest(
                MigrationSql: deniedSql,
                MigrationPath: null,
                BaseSchemaPath: workspace.BaseSchemaRelativePath,
                PolicyPath: workspace.PolicyRelativePath,
                ContractPath: workspace.ContractRelativePath),
            CancellationToken.None);

        Assert.True(
            response.Attestation.Decision is AttestationDecision.Deny or AttestationDecision.Review);
        Assert.False(string.IsNullOrWhiteSpace(response.AttestationId));
        Assert.Equal(
            CanonicalJson.Sha256Hex(VerifyMigrationUseCase.EphemeralTargetFingerprintSeed),
            response.Attestation.TargetAliasFingerprint);
    }

    [Fact]
    public async Task Verify_migration_allow_path_uses_ephemeral_docker_via_real_host_di()
    {
        using MigrationWorkspace workspace = MigrationWorkspace.Create();
        await using ServiceProvider sp = E2EHostHarness.BuildFull(workspace.AsTemp());
        IVerifyMigrationUseCase useCase = sp.GetRequiredService<IVerifyMigrationUseCase>();

        VerifyMigrationResponse response = await useCase.ExecuteAsync(
            new VerifyMigrationRequest(
                MigrationSql: null,
                MigrationPath: workspace.MigrationRelativePath,
                BaseSchemaPath: workspace.BaseSchemaRelativePath,
                PolicyPath: workspace.PolicyRelativePath,
                ContractPath: workspace.ContractRelativePath),
            CancellationToken.None);

        Assert.False(string.IsNullOrWhiteSpace(response.AttestationId));
        Assert.Equal(AttestationDecision.Pass, response.Attestation.Decision);
        Assert.Equal(
            CanonicalJson.Sha256Hex(VerifyMigrationUseCase.EphemeralTargetFingerprintSeed),
            response.Attestation.TargetAliasFingerprint);
        E2EHostHarness.AssertNoConnectionStringLeak(CanonicalJson.Serialize(response));
    }

    [Fact]
    public void Verify_migration_cli_deny_path_writes_attestation_json()
    {
        using MigrationWorkspace workspace = MigrationWorkspace.Create();
        using IDisposable env = E2EHostHarness.ConfigureCliEnvironment(workspace.AsTemp(), DiProfile.Full);

        string deniedSql = File.ReadAllText(
            Path.Combine(E2EHostHarness.FindRepoRoot(), "tests", "fixtures", "migrations", "denied", "create-extension.sql"));

        using StringWriter stdout = new();
        using StringWriter stderr = new();
        int exit = Program.Run(
            [
                "--mode", "Full",
                "verify-migration",
                "--migration-sql", deniedSql,
                "--base-schema", workspace.BaseSchemaRelativePath,
                "--policy", workspace.PolicyRelativePath,
                "--contract", workspace.ContractRelativePath,
            ],
            stdout,
            stderr);

        Assert.Equal(0, exit);
        string json = stdout.ToString();
        using JsonDocument doc = JsonDocument.Parse(json.Trim());
        Assert.False(string.IsNullOrWhiteSpace(doc.RootElement.GetProperty("attestationId").GetString()));
        int decision = doc.RootElement.GetProperty("attestation").GetProperty("decision").GetInt32();
        Assert.True(decision is (int)AttestationDecision.Deny or (int)AttestationDecision.Review);
        E2EHostHarness.AssertNoConnectionStringLeak(json);
        E2EHostHarness.AssertNoConnectionStringLeak(stderr.ToString());
    }

    [Fact]
    public async Task Verify_migration_mcp_tool_deny_path_returns_attestation_json()
    {
        using MigrationWorkspace workspace = MigrationWorkspace.Create();
        await using ServiceProvider sp = E2EHostHarness.BuildFull(workspace.AsTemp());
        VerifyMigrationTool tool = new(sp.GetRequiredService<IVerifyMigrationUseCase>());

        string deniedSql = File.ReadAllText(
            Path.Combine(E2EHostHarness.FindRepoRoot(), "tests", "fixtures", "migrations", "denied", "multi-statement.sql"));

        string json = await tool.VerifyMigration(
            migrationSql: deniedSql,
            migrationPath: null,
            baseSchemaPath: workspace.BaseSchemaRelativePath,
            policyPath: workspace.PolicyRelativePath,
            contractPath: workspace.ContractRelativePath,
            CancellationToken.None);

        using JsonDocument doc = JsonDocument.Parse(json);
        Assert.False(string.IsNullOrWhiteSpace(doc.RootElement.GetProperty("attestationId").GetString()));
        int decision = doc.RootElement.GetProperty("attestation").GetProperty("decision").GetInt32();
        Assert.True(decision is (int)AttestationDecision.Deny or (int)AttestationDecision.Review);
        E2EHostHarness.AssertNoConnectionStringLeak(json);
    }

    /// <summary>
    /// Migration-specific config root (policy/contract/base/migration). Owns disposal of the temp tree.
    /// </summary>
    private sealed class MigrationWorkspace : IDisposable
    {
        private readonly E2EHostHarness.TempWorkspace _inner;

        private MigrationWorkspace(E2EHostHarness.TempWorkspace inner)
        {
            _inner = inner;
        }

        public string PolicyRelativePath => "policy.yaml";

        public string ContractRelativePath => "contract.yaml";

        public string BaseSchemaRelativePath => "base.sql";

        public string MigrationRelativePath => "migration.sql";

        public static MigrationWorkspace Create(
            IReadOnlyDictionary<string, string>? aliasToDsnEnvVar = null)
        {
            E2EHostHarness.TempWorkspace inner = E2EHostHarness.CreateWorkspace(
                includeContract: false,
                aliasToDsnEnvVar: aliasToDsnEnvVar);
            string fixtures = Path.Combine(E2EHostHarness.FindRepoRoot(), "tests", "fixtures");
            File.Copy(
                Path.Combine(fixtures, "policies", "migration-ddl.yaml"),
                Path.Combine(inner.ConfigRoot, "policy.yaml"),
                overwrite: true);
            File.Copy(
                Path.Combine(fixtures, "contracts", "valid-mvp-b-schema-orphans.yaml"),
                Path.Combine(inner.ConfigRoot, "contract.yaml"),
                overwrite: true);
            File.Copy(
                Path.Combine(fixtures, "migrations", "base", "schema.sql"),
                Path.Combine(inner.ConfigRoot, "base.sql"),
                overwrite: true);
            File.Copy(
                Path.Combine(fixtures, "migrations", "valid", "up.sql"),
                Path.Combine(inner.ConfigRoot, "migration.sql"),
                overwrite: true);
            return new MigrationWorkspace(inner);
        }

        public E2EHostHarness.TempWorkspace AsTemp() => _inner;

        public void Dispose() => _inner.Dispose();
    }
}
