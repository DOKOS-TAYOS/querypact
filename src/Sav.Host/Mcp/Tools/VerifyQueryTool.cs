using System.ComponentModel;
using ModelContextProtocol.Server;
using Sav.Application.Abstractions;
using Sav.Application.Verify;
using Sav.Domain.Errors;
using Sav.Domain.Serialization;

namespace Sav.Host.Mcp.Tools;

/// <summary>
/// MCP tool <c>verify_query</c> (Full mode).
/// </summary>
[McpServerToolType]
public sealed class VerifyQueryTool
{
    private readonly IVerifyQueryUseCase _useCase;

    public VerifyQueryTool(IVerifyQueryUseCase useCase)
    {
        _useCase = useCase ?? throw new ArgumentNullException(nameof(useCase));
    }

    [McpServerTool(Name = "verify_query"), Description("Verify a query on a read-only target alias and attest.")]
    public async Task<string> VerifyQuery(
        [Description("SQL text to verify.")] string sql,
        [Description("Operator target alias (never a DSN).")] string targetAliasName,
        [Description("Policy path under ConfigRoot.")] string policyPath,
        [Description("Contract path under ConfigRoot.")] string contractPath,
        CancellationToken cancellationToken)
    {
        try
        {
            VerifyQueryResponse response = await _useCase.ExecuteAsync(
                    new VerifyQueryRequest(sql, targetAliasName, policyPath, contractPath),
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
