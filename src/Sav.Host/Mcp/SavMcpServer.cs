using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Sav.Application.Abstractions;
using Sav.Host.Composition;
using Sav.Host.Mcp.Tools;
using MsHost = Microsoft.Extensions.Hosting.Host;

namespace Sav.Host.Mcp;

/// <summary>
/// MCP stdio server composition. Protocol on stdout; logs on stderr.
/// </summary>
public static class SavMcpServer
{
    /// <summary>
    /// Tool-name catalog for contract tests without starting a long-running server.
    /// </summary>
    public static IReadOnlyList<string> GetToolNames(DiProfile profile) =>
        profile switch
        {
            DiProfile.AnalyzeOnly => ["analyze_sql"],
            DiProfile.Full =>
            [
                "analyze_sql",
                "verify_query",
                "verify_equivalence",
                "verify_migration",
                "get_attestation",
            ],
            _ => [],
        };

    /// <summary>
    /// True when console logging is configured to stderr (stdout reserved for MCP protocol).
    /// </summary>
    public static bool LogsToStandardError => true;

    public static LogLevel StandardErrorLogThreshold => LogLevel.Trace;

    public static async Task RunAsync(
        DiProfile profile,
        IServiceProvider applicationServices,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(applicationServices);

        HostApplicationBuilder builder = MsHost.CreateApplicationBuilder([]);
        builder.Logging.ClearProviders();
        builder.Logging.AddConsole(options =>
        {
            options.LogToStandardErrorThreshold = StandardErrorLogThreshold;
        });

        AddForwardedApplicationServices(builder.Services, applicationServices, profile);

        IMcpServerBuilder mcp = builder.Services
            .AddMcpServer()
            .WithStdioServerTransport();

        RegisterTools(mcp, profile);

        using IHost host = builder.Build();
        await host.RunAsync(cancellationToken).ConfigureAwait(false);
    }

    public static void RegisterTools(IMcpServerBuilder mcp, DiProfile profile)
    {
        ArgumentNullException.ThrowIfNull(mcp);

        mcp.WithTools<AnalyzeSqlTool>();
        if (profile == DiProfile.Full)
        {
            mcp.WithTools<VerifyQueryTool>();
            mcp.WithTools<VerifyEquivalenceTool>();
            mcp.WithTools<VerifyMigrationTool>();
            mcp.WithTools<GetAttestationTool>();
        }
    }

    /// <summary>
    /// Forwards application use cases into the MCP host container for tool constructor injection.
    /// </summary>
    public static void AddForwardedApplicationServices(
        IServiceCollection mcpServices,
        IServiceProvider applicationServices,
        DiProfile profile)
    {
        ArgumentNullException.ThrowIfNull(mcpServices);
        ArgumentNullException.ThrowIfNull(applicationServices);

        mcpServices.AddSingleton(applicationServices.GetRequiredService<IAnalyzeSqlUseCase>());
        if (profile == DiProfile.Full)
        {
            mcpServices.AddSingleton(applicationServices.GetRequiredService<IVerifyQueryUseCase>());
            mcpServices.AddSingleton(applicationServices.GetRequiredService<IVerifyEquivalenceUseCase>());
            mcpServices.AddSingleton(applicationServices.GetRequiredService<IVerifyMigrationUseCase>());
            mcpServices.AddSingleton(applicationServices.GetRequiredService<IGetAttestationUseCase>());
        }
    }
}
