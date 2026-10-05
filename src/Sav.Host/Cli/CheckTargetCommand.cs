using System.CommandLine;
using Npgsql;
using Sav.Domain.Errors;
using Sav.Domain.Targets;
using Sav.Host.Configuration;
using Sav.Infrastructure.Postgres.Targets;

namespace Sav.Host.Cli;

/// <summary>
/// Operator-only target privilege diagnostic. Does not require Full-mode HMAC configuration
/// and does not change the runtime session guard or the configured alias.
/// </summary>
public static class CheckTargetCommand
{
    public static Command Create(Func<SavModeOptions> optionsFactory)
    {
        ArgumentNullException.ThrowIfNull(optionsFactory);

        Option<string> targetOption = new("--target")
        {
            Description = "Operator target alias (never a DSN).",
            Required = true,
        };
        Option<bool> strictOption = new("--strict")
        {
            Description = "Reject privilege warnings in addition to mandatory errors.",
        };
        Command command = new("check-target", "Inspect the configured target's read-only mode and privileges.")
        {
            targetOption,
            strictOption,
        };

        command.SetAction(async (parseResult, cancellationToken) =>
        {
            TextWriter stdout = parseResult.InvocationConfiguration.Output;
            TextWriter stderr = parseResult.InvocationConfiguration.Error;
            try
            {
                SavModeOptions options = optionsFactory();
                TargetsBindingOptions bindings = new(options.AliasToDsnEnvVar);
                TargetAlias target = new TargetAliasResolver(bindings)
                    .Resolve(parseResult.GetValue(targetOption)!);

                await using NpgsqlConnection connection = new AliasConnectionFactory(bindings).Create(target);
                await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
                TargetPrivilegeReport report = await new TargetPrivilegeInspector().InspectAsync(
                    connection,
                    parseResult.GetValue(strictOption),
                    cancellationToken).ConfigureAwait(false);

                CliJson.WriteSuccess(stdout, report);
                return report.Passed ? 0 : 1;
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
                // Do not expose Npgsql connection strings, server messages or catalog names.
                CliJson.WriteError(stderr, "preflight_failed", "Target privilege inspection failed.");
                return 1;
            }
        });

        return command;
    }
}
