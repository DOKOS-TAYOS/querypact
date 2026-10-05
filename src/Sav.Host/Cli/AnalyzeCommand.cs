using System.CommandLine;
using Microsoft.Extensions.DependencyInjection;
using Sav.Application.Abstractions;
using Sav.Application.Analyze;
using Sav.Domain.Errors;

namespace Sav.Host.Cli;

/// <summary>
/// <c>querypact analyze</c>: policy decision only (no attestation, no Postgres session).
/// </summary>
public static class AnalyzeCommand
{
    public static Command Create(Func<IServiceProvider> servicesFactory)
    {
        ArgumentNullException.ThrowIfNull(servicesFactory);

        Option<string> sqlOption = new("--sql")
        {
            Description = "SQL text to analyze.",
            Required = true,
        };
        Option<string> policyOption = new("--policy")
        {
            Description = "Policy path under ConfigRoot.",
            Required = true,
        };
        Option<string?> contractOption = new("--contract")
        {
            Description = "Optional contract path under ConfigRoot.",
        };

        Command command = new("analyze", "Analyze SQL against policy without executing it.")
        {
            sqlOption,
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
                IAnalyzeSqlUseCase useCase = sp.GetRequiredService<IAnalyzeSqlUseCase>();
                AnalyzeSqlResponse response = await useCase.ExecuteAsync(
                        new AnalyzeSqlRequest(
                            parseResult.GetValue(sqlOption)!,
                            parseResult.GetValue(policyOption)!,
                            parseResult.GetValue(contractOption)),
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
                CliJson.WriteError(stderr, "internal_error", "Analyze failed.");
                return 1;
            }
        });

        return command;
    }
}
