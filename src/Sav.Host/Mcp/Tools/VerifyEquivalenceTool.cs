using System.ComponentModel;
using ModelContextProtocol.Server;
using Sav.Application.Abstractions;
using Sav.Application.Verify;
using Sav.Domain.Errors;
using Sav.Domain.Serialization;

namespace Sav.Host.Mcp.Tools;

/// <summary>
/// MCP tool <c>verify_equivalence</c> (Full mode / MVP-B).
/// </summary>
[McpServerToolType]
public sealed class VerifyEquivalenceTool
{
    private readonly IVerifyEquivalenceUseCase _useCase;

    public VerifyEquivalenceTool(IVerifyEquivalenceUseCase useCase)
    {
        _useCase = useCase ?? throw new ArgumentNullException(nameof(useCase));
    }

    [McpServerTool(Name = "verify_equivalence"), Description("Verify query equivalence on a read-only target alias and attest.")]
    public async Task<string> VerifyEquivalence(
        [Description("Left SQL text.")] string leftSql,
        [Description("Right SQL text.")] string rightSql,
        [Description("Operator target alias (never a DSN).")] string targetAliasName,
        [Description("Policy path under ConfigRoot.")] string policyPath,
        [Description("Contract path under ConfigRoot.")] string contractPath,
        CancellationToken cancellationToken)
    {
        try
        {
            VerifyEquivalenceResponse response = await _useCase.ExecuteAsync(
                    new VerifyEquivalenceRequest(leftSql, rightSql, targetAliasName, policyPath, contractPath),
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
