using System.CommandLine;
using Microsoft.Extensions.DependencyInjection;
using Sav.Application.Abstractions;
using Sav.Application.Verify;
using Sav.Domain.Errors;

namespace Sav.Host.Cli;

/// <summary>
/// <c>querypact verify-equivalence</c>: Full mode / MVP-B.
/// </summary>
public static class VerifyEquivalenceCommand
{
    public static Command Create(Func<IServiceProvider> servicesFactory)
    {
        ArgumentNullException.ThrowIfNull(servicesFactory);

        Option<string> leftOption = new("--left-sql") { Description = "Left SQL text.", Required = true };
        Option<string> rightOption = new("--right-sql") { Description = "Right SQL text.", Required = true };
        Option<string> targetOption = new("--target")
        {
            Description = "Operator target alias (never a DSN).",
            Required = true,
        };
        Option<string> policyOption = new("--policy") { Description = "Policy path under ConfigRoot.", Required = true };
        Option<string> contractOption = new("--contract")
        {
            Description = "Contract path under ConfigRoot.",
            Required = true,
        };

        Command command = new("verify-equivalence", "Verify query equivalence on a read-only target alias and attest.")
        {
            leftOption,
            rightOption,
            targetOption,
            policyOption,
            contractOption,
        };

        command.SetAction(async (parseResult, cancellationToken) =>
        {
            TextWriter stdout = parseResult.InvocationConfiguration.Output;
            TextWriter stderr = parseResult.InvocationConfiguration.Error;
            try
            {
                IServiceProvider sp = servicesFactory();
                IVerifyEquivalenceUseCase useCase = sp.GetRequiredService<IVerifyEquivalenceUseCase>();
                VerifyEquivalenceResponse response = await useCase.ExecuteAsync(
                        new VerifyEquivalenceRequest(
                            parseResult.GetValue(leftOption)!,
                            parseResult.GetValue(rightOption)!,
                            parseResult.GetValue(targetOption)!,
                            parseResult.GetValue(policyOption)!,
                            parseResult.GetValue(contractOption)!),
                        cancellationToken)
                    .ConfigureAwait(false);
                CliJson.WriteSuccess(stdout, response);
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
                CliJson.WriteError(stderr, "internal_error", "Verify-equivalence failed.");
                return 1;
            }
        });

        return command;
    }
}
