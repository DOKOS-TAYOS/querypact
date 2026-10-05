using Sav.Host.Composition;
using Sav.Host.Mcp;
using Sav.Host.Mcp.Tools;

namespace Sav.Host.Tests;

public sealed class McpVerifyRestContractTests
{
    [Fact]
    public void Full_catalog_is_five_tool_set()
    {
        IReadOnlyList<string> tools = SavMcpServer.GetToolNames(DiProfile.Full);
        Assert.Equal(
            [
                "analyze_sql",
                "verify_query",
                "verify_equivalence",
                "verify_migration",
                "get_attestation",
            ],
            tools);
        Assert.DoesNotContain("execute_sql", tools);
    }

    [Fact]
    public void AnalyzeOnly_catalog_excludes_equivalence_and_migration()
    {
        IReadOnlyList<string> tools = SavMcpServer.GetToolNames(DiProfile.AnalyzeOnly);
        Assert.DoesNotContain("verify_equivalence", tools);
        Assert.DoesNotContain("verify_migration", tools);
        Assert.DoesNotContain("verify_query", tools);
        Assert.DoesNotContain("get_attestation", tools);
        Assert.DoesNotContain("execute_sql", tools);
        Assert.Equal(["analyze_sql"], tools);
    }

    [Fact]
    public void Mcp_logs_go_to_stderr_not_stdout_protocol_channel()
    {
        Assert.True(SavMcpServer.LogsToStandardError);
    }

    [Fact]
    public async Task Verify_migration_tool_enforces_xor_args()
    {
        // Tool-level XOR before use case: no DI required for this contract check.
        VerifyMigrationTool tool = new(new ThrowingMigrationUseCase());
        string both = await tool.VerifyMigration(
            migrationSql: "SELECT 1",
            migrationPath: "m.sql",
            baseSchemaPath: "base.sql",
            policyPath: "p.yaml",
            contractPath: "c.yaml",
            CancellationToken.None);
        Assert.Contains("unsupported_construct", both, StringComparison.Ordinal);

        string neither = await tool.VerifyMigration(
            migrationSql: null,
            migrationPath: null,
            baseSchemaPath: "base.sql",
            policyPath: "p.yaml",
            contractPath: "c.yaml",
            CancellationToken.None);
        Assert.Contains("unsupported_construct", neither, StringComparison.Ordinal);
    }

    private sealed class ThrowingMigrationUseCase : Application.Abstractions.IVerifyMigrationUseCase
    {
        public Task<Application.Migrations.VerifyMigrationResponse> ExecuteAsync(
            Application.Migrations.VerifyMigrationRequest request,
            CancellationToken cancellationToken) =>
            throw new InvalidOperationException("Use case must not run for XOR failures.");
    }
}
