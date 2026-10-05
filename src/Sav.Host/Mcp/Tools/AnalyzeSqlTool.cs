using System.ComponentModel;
using ModelContextProtocol.Server;
using Sav.Application.Abstractions;
using Sav.Application.Analyze;
using Sav.Domain.Errors;
using Sav.Domain.Serialization;

namespace Sav.Host.Mcp.Tools;

/// <summary>
/// MCP tool <c>analyze_sql</c>.
/// </summary>
[McpServerToolType]
public sealed class AnalyzeSqlTool
{
    private readonly IAnalyzeSqlUseCase _useCase;

    public AnalyzeSqlTool(IAnalyzeSqlUseCase useCase)
    {
        _useCase = useCase ?? throw new ArgumentNullException(nameof(useCase));
    }

    [McpServerTool(Name = "analyze_sql"), Description("Analyze SQL against policy without executing it.")]
    public async Task<string> AnalyzeSql(
        [Description("SQL text to analyze.")] string sql,
        [Description("Policy path under ConfigRoot.")] string policyPath,
        [Description("Optional contract path under ConfigRoot.")] string? contractPath,
        CancellationToken cancellationToken)
    {
        try
        {
            AnalyzeSqlResponse response = await _useCase.ExecuteAsync(
                    new AnalyzeSqlRequest(sql, policyPath, contractPath),
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
