using System.CommandLine;
using Microsoft.Extensions.DependencyInjection;
using Sav.Application.Abstractions;
using Sav.Domain.Attestations;
using Sav.Domain.Errors;

namespace Sav.Host.Cli;

/// <summary>
/// <c>querypact attestation get</c>: Full mode only.
/// </summary>
public static class AttestationGetCommand
{
    public static Command Create(Func<IServiceProvider> servicesFactory)
    {
        ArgumentNullException.ThrowIfNull(servicesFactory);

        Option<string> idOption = new("--id")
        {
            Description = "Attestation id (UUID form; not a filesystem path).",
            Required = true,
        };

        Command get = new("get", "Get a stored attestation by id after integrity verification.")
        {
            idOption,
        };

        get.SetAction(async (parseResult, cancellationToken) =>
        {
            TextWriter stdout = parseResult.InvocationConfiguration.Output;
            TextWriter stderr = parseResult.InvocationConfiguration.Error;
            try
            {
                IServiceProvider sp = servicesFactory();
                IGetAttestationUseCase useCase = sp.GetRequiredService<IGetAttestationUseCase>();
                Attestation? attestation = await useCase.ExecuteAsync(
                        parseResult.GetValue(idOption)!,
                        cancellationToken)
                    .ConfigureAwait(false);
                if (attestation is null)
                {
                    CliJson.WriteError(stderr, "attestation_not_found", "Attestation was not found.");
                    return 1;
                }

                CliJson.WriteSuccess(stdout, attestation);
                return 0;
            }
            catch (SavException ex)
            {
                CliJson.WriteSavException(stderr, ex);
                return 1;
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception)
            {
                CliJson.WriteError(stderr, "internal_error", "Attestation get failed.");
                return 1;
            }
        });

        Command attestation = new("attestation", "Attestation store operations.")
        {
            get,
        };
        return attestation;
    }
}
