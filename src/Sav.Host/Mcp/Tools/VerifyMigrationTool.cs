using System.ComponentModel;
using ModelContextProtocol.Server;
using Sav.Application.Abstractions;
using Sav.Application.Migrations;
using Sav.Domain.Errors;
using Sav.Domain.Serialization;

namespace Sav.Host.Mcp.Tools;

/// <summary>
/// MCP tool <c>verify_migration</c> (Full mode / MVP-B). Exactly one of migrationSql or migrationPath.
/// </summary>
[McpServerToolType]
public sealed class VerifyMigrationTool
{
    private readonly IVerifyMigrationUseCase _useCase;

    public VerifyMigrationTool(IVerifyMigrationUseCase useCase)
    {
        _useCase = useCase ?? throw new ArgumentNullException(nameof(useCase));
    }

    [McpServerTool(Name = "verify_migration"), Description("Verify a migration on ephemeral PostgreSQL and attest.")]
    public async Task<string> VerifyMigration(
        [Description("Inline migration SQL (XOR with migrationPath).")] string? migrationSql,
        [Description("Migration SQL path under ConfigRoot (XOR with migrationSql).")] string? migrationPath,
        [Description("Base schema SQL path under ConfigRoot.")] string baseSchemaPath,
        [Description("Policy path under ConfigRoot.")] string policyPath,
        [Description("Contract path under ConfigRoot.")] string contractPath,
        CancellationToken cancellationToken)
    {
        try
        {
            bool hasSql = !string.IsNullOrWhiteSpace(migrationSql);
            bool hasPath = !string.IsNullOrWhiteSpace(migrationPath);
            if (hasSql == hasPath)
            {
                return CanonicalJson.Serialize(new
                {
                    error = "unsupported_construct",
                    message = "Exactly one of migrationSql or migrationPath is required.",
                });
            }

            VerifyMigrationResponse response = await _useCase.ExecuteAsync(
                    new VerifyMigrationRequest(migrationSql, migrationPath, baseSchemaPath, policyPath, contractPath),
                    cancellationToken)
                .ConfigureAwait(false);
            return CanonicalJson.Serialize(response);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (SavException ex)
        {
            return McpToolErrors.FromSavException(ex);
        }
        catch (Exception ex)
        {
            return McpToolErrors.FromUnexpected(ex);
        }
    }
}
