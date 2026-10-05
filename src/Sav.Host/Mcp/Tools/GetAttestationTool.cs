using System.ComponentModel;
using ModelContextProtocol.Server;
using Sav.Application.Abstractions;
using Sav.Domain.Attestations;
using Sav.Domain.Errors;
using Sav.Domain.Serialization;

namespace Sav.Host.Mcp.Tools;

/// <summary>
/// MCP tool <c>get_attestation</c> (Full mode).
/// </summary>
[McpServerToolType]
public sealed class GetAttestationTool
{
    private readonly IGetAttestationUseCase _useCase;

    public GetAttestationTool(IGetAttestationUseCase useCase)
    {
        _useCase = useCase ?? throw new ArgumentNullException(nameof(useCase));
    }

    [McpServerTool(Name = "get_attestation"), Description("Get a stored attestation by id after integrity verification.")]
    public async Task<string> GetAttestation(
        [Description("Attestation id (UUID form; not a filesystem path).")] string attestationId,
        CancellationToken cancellationToken)
    {
        try
        {
            Attestation? attestation = await _useCase.ExecuteAsync(attestationId, cancellationToken)
                .ConfigureAwait(false);
            if (attestation is null)
            {
                return CanonicalJson.Serialize(new
                {
                    error = "attestation_not_found",
                    message = "Attestation was not found.",
                });
            }

            return CanonicalJson.Serialize(attestation);
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
