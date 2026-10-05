using System.CommandLine;
using Sav.Domain.Errors;
using Sav.Host.Composition;
using Sav.Host.Mcp;

namespace Sav.Host.Cli;

/// <summary>
/// <c>querypact mcp serve</c>: stdio MCP server (logs → stderr; protocol → stdout).
/// </summary>
public static class McpServeCommand
{
    public static Command Create(DiProfile profile, Func<IServiceProvider> servicesFactory)
    {
        ArgumentNullException.ThrowIfNull(servicesFactory);

        Command serve = new("serve", "Serve MCP tools over stdio.");
        serve.SetAction(async (parseResult, cancellationToken) =>
        {
            TextWriter stderr = parseResult.InvocationConfiguration.Error;
            try
            {
                IServiceProvider sp = servicesFactory();
                await SavMcpServer.RunAsync(profile, sp, cancellationToken).ConfigureAwait(false);
                return 0;
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (SavException ex)
            {
                CliJson.WriteSavException(stderr, ex);
                return 1;
            }
            catch (Exception)
            {
                CliJson.WriteError(stderr, "internal_error", "MCP serve failed.");
                return 1;
            }
        });

        Command mcp = new("mcp", "Model Context Protocol surfaces.")
        {
            serve,
        };
        return mcp;
    }
}
