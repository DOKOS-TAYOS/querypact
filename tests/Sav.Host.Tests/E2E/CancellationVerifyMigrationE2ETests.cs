using Microsoft.Extensions.DependencyInjection;
using Sav.Application.Abstractions;
using Sav.Application.Migrations;
using Sav.Host.Mcp.Tools;

namespace Sav.Host.Tests.E2E;

/// <summary>
/// M009e: cancel mid verify_migration without row leakage (use case + MCP).
/// </summary>
public sealed class CancellationVerifyMigrationE2ETests : SavEnvTestBase
{
    [Fact]
    public async Task Verify_migration_use_case_honors_cancelled_token_without_row_leak()
    {
        using MigrationCancelWorkspace workspace = MigrationCancelWorkspace.Create();
        await using ServiceProvider sp = E2EHostHarness.BuildFull(workspace.AsTemp());
        IVerifyMigrationUseCase useCase = sp.GetRequiredService<IVerifyMigrationUseCase>();

        using CancellationTokenSource cts = new();
        cts.Cancel();

        OperationCanceledException ex = await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            useCase.ExecuteAsync(
                new VerifyMigrationRequest(
                    MigrationSql: $"CREATE INDEX x ON orders (id); -- {E2EHostHarness.CanaryLiteral}",
                    MigrationPath: null,
                    BaseSchemaPath: workspace.BaseSchemaRelativePath,
                    PolicyPath: workspace.PolicyRelativePath,
                    ContractPath: workspace.ContractRelativePath),
                cts.Token));

        E2EHostHarness.AssertNoCanary(ex.ToString());
        Assert.Empty(Directory.EnumerateFiles(workspace.StoreRoot, "*", SearchOption.AllDirectories));
    }

    [Fact]
    public async Task Verify_migration_mcp_tool_honors_cancelled_token_without_row_leak()
    {
        using MigrationCancelWorkspace workspace = MigrationCancelWorkspace.Create();
        await using ServiceProvider sp = E2EHostHarness.BuildFull(workspace.AsTemp());
        VerifyMigrationTool tool = new(sp.GetRequiredService<IVerifyMigrationUseCase>());

        using CancellationTokenSource cts = new();
        cts.Cancel();

        OperationCanceledException ex = await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            tool.VerifyMigration(
                migrationSql: $"CREATE INDEX x ON orders (id); -- {E2EHostHarness.CanaryLiteral}",
                migrationPath: null,
                baseSchemaPath: workspace.BaseSchemaRelativePath,
                policyPath: workspace.PolicyRelativePath,
                contractPath: workspace.ContractRelativePath,
                cts.Token));

        E2EHostHarness.AssertNoCanary(ex.ToString());
        Assert.Empty(Directory.EnumerateFiles(workspace.StoreRoot, "*", SearchOption.AllDirectories));
    }

    private sealed class MigrationCancelWorkspace : IDisposable
    {
        private readonly E2EHostHarness.TempWorkspace _inner;

        private MigrationCancelWorkspace(E2EHostHarness.TempWorkspace inner)
        {
            _inner = inner;
        }

        public string StoreRoot => _inner.StoreRoot;

        public string PolicyRelativePath => "policy.yaml";

        public string ContractRelativePath => "contract.yaml";

        public string BaseSchemaRelativePath => "base.sql";

        public static MigrationCancelWorkspace Create()
        {
            E2EHostHarness.TempWorkspace inner = E2EHostHarness.CreateWorkspace(includeContract: false);
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
            return new MigrationCancelWorkspace(inner);
        }

        public E2EHostHarness.TempWorkspace AsTemp() => _inner;

        public void Dispose() => _inner.Dispose();
    }
}
