using System.CommandLine;
using Microsoft.Extensions.DependencyInjection;
using Sav.Application.Abstractions;
using Sav.Application.Migrations;
using Sav.Domain.Errors;

namespace Sav.Host.Cli;

/// <summary>
/// <c>querypact verify-migration</c>: Full mode / MVP-B. Exactly one of --migration-sql or --migration-path.
/// </summary>
public static class VerifyMigrationCommand
{
    public static Command Create(Func<IServiceProvider> servicesFactory)
    {
        ArgumentNullException.ThrowIfNull(servicesFactory);

        Option<string?> migrationSqlOption = new("--migration-sql")
        {
            Description = "Inline migration SQL (XOR with --migration-path).",
        };
        Option<string?> migrationPathOption = new("--migration-path")
        {
            Description = "Migration SQL file under ConfigRoot (XOR with --migration-sql).",
        };
        Option<string> baseSchemaOption = new("--base-schema")
        {
            Description = "Base schema SQL path under ConfigRoot.",
            Required = true,
        };
        Option<string> policyOption = new("--policy") { Description = "Policy path under ConfigRoot.", Required = true };
        Option<string> contractOption = new("--contract")
        {
            Description = "Contract path under ConfigRoot.",
            Required = true,
        };

        Command command = new("verify-migration", "Verify a migration on ephemeral PostgreSQL and attest.")
        {
            migrationSqlOption,
            migrationPathOption,
            baseSchemaOption,
            policyOption,
            contractOption,
        };

        command.SetAction(async (parseResult, cancellationToken) =>
        {
            TextWriter stdout = parseResult.InvocationConfiguration.Output;
            TextWriter stderr = parseResult.InvocationConfiguration.Error;
            try
            {
                string? migrationSql = parseResult.GetValue(migrationSqlOption);
                string? migrationPath = parseResult.GetValue(migrationPathOption);
                bool hasSql = !string.IsNullOrWhiteSpace(migrationSql);
                bool hasPath = !string.IsNullOrWhiteSpace(migrationPath);
                if (hasSql == hasPath)
                {
                    CliJson.WriteError(
                        stderr,
                        "unsupported_construct",
                        "Exactly one of --migration-sql or --migration-path is required.");
                    return 1;
                }

                IServiceProvider sp = servicesFactory();
                IVerifyMigrationUseCase useCase = sp.GetRequiredService<IVerifyMigrationUseCase>();
                VerifyMigrationResponse response = await useCase.ExecuteAsync(
                        new VerifyMigrationRequest(
                            migrationSql,
                            migrationPath,
                            parseResult.GetValue(baseSchemaOption)!,
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
                CliJson.WriteError(stderr, "internal_error", "Verify-migration failed.");
                return 1;
            }
        });

        return command;
    }
}
