using System.CommandLine;
using Microsoft.Extensions.DependencyInjection;
using Sav.Application.Abstractions;
using Sav.Application.Verify;
using Sav.Domain.Errors;

namespace Sav.Host.Cli;

/// <summary>
/// <c>querypact verify-query</c>: Full mode only.
/// </summary>
public static class VerifyQueryCommand
{
    public static Command Create(Func<IServiceProvider> servicesFactory)
    {
        ArgumentNullException.ThrowIfNull(servicesFactory);

        Option<string> sqlOption = new("--sql") { Description = "SQL text to verify.", Required = true };
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

        Command command = new("verify-query", "Verify a query on a read-only target alias and attest.")
        {
            sqlOption,
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
                IVerifyQueryUseCase useCase = sp.GetRequiredService<IVerifyQueryUseCase>();
                VerifyQueryResponse response = await useCase.ExecuteAsync(
                        new VerifyQueryRequest(
                            parseResult.GetValue(sqlOption)!,
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
                CliJson.WriteError(stderr, "internal_error", "Verify-query failed.");
                return 1;
            }
        });

        return command;
    }
}
