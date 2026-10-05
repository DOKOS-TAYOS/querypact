using System.CommandLine;
using System.Globalization;
using Microsoft.Extensions.DependencyInjection;
using Sav.Domain.Errors;
using Sav.Host.Cli;
using Sav.Host.Composition;
using Sav.Host.Configuration;

namespace Sav.Host;

/// <summary>
/// Host entry: CLI + MCP stdio for AnalyzeOnly and Full profiles.
/// </summary>
public static class Program
{
    public static int Main(string[] args)
    {
        return Run(args);
    }

    public static int Run(string[] args, TextWriter? output = null, TextWriter? error = null)
    {
        CultureInfo english = CultureInfo.GetCultureInfo("en-US");
        CultureInfo.CurrentUICulture = english;
        CultureInfo.CurrentCulture = english;
        CultureInfo.DefaultThreadCurrentUICulture = english;
        CultureInfo.DefaultThreadCurrentCulture = english;

        TextWriter stderr = error ?? Console.Error;

        DiProfile profile;
        try
        {
            profile = ResolveProfile(args);
        }
        catch (SavException ex)
        {
            CliJson.WriteSavException(stderr, ex);
            return 2;
        }

        ServiceProvider? provider = null;
        try
        {
            Func<IServiceProvider> servicesFactory = () =>
            {
                provider ??= BuildServiceProvider(profile, stderr);
                return provider;
            };

            // Help/version must not force Full HMAC DI construction.
            if (!IsHelpOrVersionOnly(args) && RequiresServices(args))
            {
                try
                {
                    _ = servicesFactory();
                }
                catch (SavException ex)
                {
                    CliJson.WriteSavException(stderr, ex);
                    return 2;
                }
            }

            RootCommand rootCommand = CreateRootCommand(profile, servicesFactory);
            ParseResult parseResult = rootCommand.Parse(args);

            InvocationConfiguration configuration = new();
            if (output is not null)
            {
                configuration.Output = output;
            }

            if (error is not null)
            {
                configuration.Error = error;
            }

            return parseResult.Invoke(configuration);
        }
        finally
        {
            if (provider is not null)
            {
                DisposeServiceProvider(provider);
            }
        }
    }

    internal static void DisposeServiceProvider(ServiceProvider provider)
    {
        if (provider is IAsyncDisposable asyncDisposable)
        {
            asyncDisposable.DisposeAsync().AsTask().GetAwaiter().GetResult();
        }
        else
        {
            provider.Dispose();
        }
    }

    internal static RootCommand CreateRootCommand(DiProfile profile, Func<IServiceProvider> servicesFactory)
    {
        RootCommand rootCommand = new("QueryPact: Policy and contract verification for SQL.");
        Option<string?> modeOption = new("--mode")
        {
            Description = "Host mode: AnalyzeOnly | Full (overrides SAV_MODE).",
        };
        rootCommand.Options.Add(modeOption);

        rootCommand.Subcommands.Add(AnalyzeCommand.Create(servicesFactory));
        rootCommand.Subcommands.Add(CheckTargetCommand.Create(() => SavModeOptions.FromEnvironment(profile)));
        rootCommand.Subcommands.Add(McpServeCommand.Create(profile, servicesFactory));

        if (profile == DiProfile.Full)
        {
            rootCommand.Subcommands.Add(VerifyQueryCommand.Create(servicesFactory));
            rootCommand.Subcommands.Add(VerifyEquivalenceCommand.Create(servicesFactory));
            rootCommand.Subcommands.Add(VerifyMigrationCommand.Create(servicesFactory));
            rootCommand.Subcommands.Add(AttestationGetCommand.Create(servicesFactory));
        }

        return rootCommand;
    }

    /// <summary>
    /// Test hook: build DI for a profile (Full requires HMAC env or explicit key).
    /// </summary>
    public static ServiceProvider BuildServiceProvider(
        DiProfile profile,
        TextWriter? error = null,
        SavModeOptions? options = null,
        byte[]? hmacKey = null)
    {
        SavModeOptions resolved = options ?? SavModeOptions.FromEnvironment(profile);
        if (resolved.Mode != profile)
        {
            resolved = new SavModeOptions
            {
                Mode = profile,
                ConfigRoot = resolved.ConfigRoot,
                AttestationStoreRoot = resolved.AttestationStoreRoot,
                AliasToDsnEnvVar = resolved.AliasToDsnEnvVar,
            };
        }

        ServiceCollection services = new();
        byte[]? key = profile == DiProfile.Full
            ? hmacKey ?? ServiceCollectionExtensions.RequireHmacKeyFromEnvironment()
            : null;
        services.AddSavByProfile(resolved, key);

        return services.BuildServiceProvider(new ServiceProviderOptions
        {
            ValidateScopes = true,
            ValidateOnBuild = true,
        });
    }

    private static DiProfile ResolveProfile(string[] args)
    {
        string? modeFromArgs = TryGetModeOption(args);
        if (!string.IsNullOrWhiteSpace(modeFromArgs))
        {
            return SavModeOptions.ResolveMode(modeFromArgs);
        }

        return SavModeOptions.ResolveModeFromEnvironment();
    }

    private static string? TryGetModeOption(string[] args)
    {
        for (int i = 0; i < args.Length; i++)
        {
            string arg = args[i];
            if (arg.Equals("--mode", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
            {
                return args[i + 1];
            }

            if (arg.StartsWith("--mode=", StringComparison.OrdinalIgnoreCase))
            {
                return arg["--mode=".Length..];
            }
        }

        return null;
    }

    private static bool IsHelpOrVersionOnly(string[] args)
    {
        if (args.Length == 0)
        {
            return true;
        }

        return args.Any(arg =>
            arg.Equals("--help", StringComparison.OrdinalIgnoreCase)
            || arg.Equals("-h", StringComparison.OrdinalIgnoreCase)
            || arg.Equals("-?", StringComparison.OrdinalIgnoreCase)
            || arg.Equals("--version", StringComparison.OrdinalIgnoreCase)
            || arg.Equals("-v", StringComparison.OrdinalIgnoreCase));
    }

    private static bool RequiresServices(string[] args)
    {
        for (int i = 0; i < args.Length; i++)
        {
            string arg = args[i];
            if (arg.Equals("--mode", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
            {
                i++;
                continue;
            }

            if (arg.StartsWith("--mode=", StringComparison.OrdinalIgnoreCase)
                || arg.StartsWith('-'))
            {
                continue;
            }

            return arg.Equals("analyze", StringComparison.OrdinalIgnoreCase)
                || arg.Equals("verify-query", StringComparison.OrdinalIgnoreCase)
                || arg.Equals("verify-equivalence", StringComparison.OrdinalIgnoreCase)
                || arg.Equals("verify-migration", StringComparison.OrdinalIgnoreCase)
                || arg.Equals("attestation", StringComparison.OrdinalIgnoreCase)
                || arg.Equals("mcp", StringComparison.OrdinalIgnoreCase);
        }

        return false;
    }
}
