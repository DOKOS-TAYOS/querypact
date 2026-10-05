using Microsoft.Extensions.DependencyInjection;
using Sav.Application.Abstractions;
using Sav.Host.Composition;
using Sav.Host.Configuration;
using Sav.Infrastructure.Postgres.Redaction;
using Sav.Infrastructure.Storage.Attestations;

namespace Sav.Host.Tests.E2E;

/// <summary>
/// Shared helpers for M009d E2E tests against real host DI / CLI.
/// </summary>
internal static class E2EHostHarness
{
    public const string CanaryLiteral = "CANARY_LITERAL_do_not_egress@example.invalid";

    public static string FindRepoRoot()
    {
        DirectoryInfo? dir = new(AppContext.BaseDirectory);
        while (dir is not null)
        {
            if (File.Exists(Path.Combine(dir.FullName, "QueryPact.sln")))
            {
                return dir.FullName;
            }

            dir = dir.Parent;
        }

        throw new InvalidOperationException("Could not locate QueryPact.sln.");
    }

    public static TempWorkspace CreateWorkspace(
        bool includeContract = true,
        bool includeTargets = false,
        IReadOnlyDictionary<string, string>? aliasToDsnEnvVar = null)
    {
        string root = Path.Combine(Path.GetTempPath(), "sav-e2e-" + Guid.NewGuid().ToString("N"));
        string storeRoot = Path.Combine(root, "attestations");
        Directory.CreateDirectory(root);
        Directory.CreateDirectory(storeRoot);

        string fixtures = Path.Combine(FindRepoRoot(), "tests", "fixtures");
        File.Copy(
            Path.Combine(fixtures, "policies", "valid-basic.yaml"),
            Path.Combine(root, "policy.yaml"),
            overwrite: true);

        if (includeContract)
        {
            File.Copy(
                Path.Combine(fixtures, "contracts", "valid-mvp-a-query-succeeds-empty-result.yaml"),
                Path.Combine(root, "contract.yaml"),
                overwrite: true);
        }

        Dictionary<string, string> aliases = aliasToDsnEnvVar is null
            ? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            : new Dictionary<string, string>(aliasToDsnEnvVar, StringComparer.OrdinalIgnoreCase);

        if (includeTargets && aliases.Count > 0)
        {
            string json = "{" + string.Join(
                ",",
                aliases.Select(static kv =>
                    $"\"{EscapeJson(kv.Key)}\":\"{EscapeJson(kv.Value)}\"")) + "}";
            File.WriteAllText(Path.Combine(root, SavModeOptions.TargetsFileName), json);
        }

        byte[] hmacKey = Enumerable.Repeat((byte)0xE2, 32).ToArray();
        return new TempWorkspace(root, storeRoot, hmacKey, aliases);
    }

    public static SavModeOptions AnalyzeOnlyOptions(TempWorkspace workspace) =>
        new()
        {
            Mode = DiProfile.AnalyzeOnly,
            ConfigRoot = workspace.ConfigRoot,
            AttestationStoreRoot = workspace.StoreRoot,
            AliasToDsnEnvVar = new Dictionary<string, string>(workspace.AliasToDsnEnvVar, StringComparer.OrdinalIgnoreCase),
        };

    public static SavModeOptions FullOptions(TempWorkspace workspace) =>
        new()
        {
            Mode = DiProfile.Full,
            ConfigRoot = workspace.ConfigRoot,
            AttestationStoreRoot = workspace.StoreRoot,
            AliasToDsnEnvVar = new Dictionary<string, string>(workspace.AliasToDsnEnvVar, StringComparer.OrdinalIgnoreCase),
        };

    public static ServiceProvider BuildAnalyzeOnly(TempWorkspace workspace) =>
        Program.BuildServiceProvider(DiProfile.AnalyzeOnly, options: AnalyzeOnlyOptions(workspace));

    public static ServiceProvider BuildFull(TempWorkspace workspace) =>
        Program.BuildServiceProvider(
            DiProfile.Full,
            options: FullOptions(workspace),
            hmacKey: workspace.HmacKey);

    public static (ServiceProvider Sp, CountingRedactor Counter) BuildAnalyzeOnlyWithCountingRedactor(
        TempWorkspace workspace)
    {
        ServiceCollection services = new();
        services.AddSavAnalyzeOnly(AnalyzeOnlyOptions(workspace));
        ReplaceWithCountingRedactor(services);
        ServiceProvider sp = services.BuildServiceProvider(new ServiceProviderOptions
        {
            ValidateScopes = true,
            ValidateOnBuild = true,
        });
        CountingRedactor counter = (CountingRedactor)sp.GetRequiredService<IRedactor>();
        return (sp, counter);
    }

    public static (ServiceProvider Sp, CountingRedactor Counter) BuildFullWithCountingRedactor(
        TempWorkspace workspace)
    {
        ServiceCollection services = new();
        services.AddSavFull(FullOptions(workspace), workspace.HmacKey);
        ReplaceWithCountingRedactor(services);
        ServiceProvider sp = services.BuildServiceProvider(new ServiceProviderOptions
        {
            ValidateScopes = true,
            ValidateOnBuild = true,
        });
        CountingRedactor counter = (CountingRedactor)sp.GetRequiredService<IRedactor>();
        return (sp, counter);
    }

    public static IDisposable ConfigureCliEnvironment(TempWorkspace workspace, DiProfile mode)
    {
        List<IDisposable> scopes =
        [
            EnvScope.Set(
                SavModeOptions.ModeEnvironmentVariable,
                mode == DiProfile.AnalyzeOnly ? nameof(DiProfile.AnalyzeOnly) : nameof(DiProfile.Full)),
            EnvScope.Set(SavModeOptions.ConfigRootEnvironmentVariable, workspace.ConfigRoot),
            EnvScope.Set(SavModeOptions.AttestationStoreRootEnvironmentVariable, workspace.StoreRoot),
            EnvScope.Set(SavModeOptions.TargetsJsonEnvironmentVariable, null),
        ];

        if (mode == DiProfile.Full)
        {
            scopes.Add(EnvScope.Set(
                AttestationHmacKeyDecoder.EnvironmentVariableName,
                "base64:" + Convert.ToBase64String(workspace.HmacKey)));
        }

        return new CompositeDisposable(scopes);
    }

    public static void AssertNoCanary(string text)
    {
        Assert.DoesNotContain(CanaryLiteral, text, StringComparison.OrdinalIgnoreCase);
    }

    public static void AssertNoConnectionStringLeak(string text)
    {
        string[] patterns =
        [
            "Host=",
            "Password=",
            "Username=",
            "User ID=",
            "postgres://",
            "postgresql://",
        ];

        foreach (string pattern in patterns)
        {
            Assert.DoesNotContain(pattern, text, StringComparison.OrdinalIgnoreCase);
        }
    }

    private static void ReplaceWithCountingRedactor(IServiceCollection services)
    {
        ServiceDescriptor original = services.Single(d => d.ServiceType == typeof(IRedactor));
        services.Remove(original);

        CountingRedactor? holder = null;
        services.AddSingleton<IRedactor>(sp =>
        {
            if (holder is not null)
            {
                return holder;
            }

            IRedactor inner = CreateInnerRedactor(sp, original);
            holder = new CountingRedactor(inner);
            return holder;
        });
    }

    private static IRedactor CreateInnerRedactor(IServiceProvider sp, ServiceDescriptor original)
    {
        if (original.ImplementationFactory is not null)
        {
            return (IRedactor)original.ImplementationFactory(sp)!;
        }

        if (original.ImplementationInstance is IRedactor instance)
        {
            return instance;
        }

        if (original.ImplementationType is not null)
        {
            return (IRedactor)ActivatorUtilities.CreateInstance(sp, original.ImplementationType);
        }

        return new PostgresErrorRedactor(sp.GetRequiredService<StrictRedactor>());
    }

    private static string EscapeJson(string value) =>
        value.Replace("\\", "\\\\", StringComparison.Ordinal).Replace("\"", "\\\"", StringComparison.Ordinal);

    internal sealed class TempWorkspace : IDisposable
    {
        public TempWorkspace(
            string configRoot,
            string storeRoot,
            byte[] hmacKey,
            Dictionary<string, string> aliasToDsnEnvVar)
        {
            ConfigRoot = configRoot;
            StoreRoot = storeRoot;
            HmacKey = hmacKey;
            AliasToDsnEnvVar = aliasToDsnEnvVar;
        }

        public string ConfigRoot { get; }

        public string StoreRoot { get; }

        public byte[] HmacKey { get; }

        public Dictionary<string, string> AliasToDsnEnvVar { get; }

        public string PolicyRelativePath => "policy.yaml";

        public string ContractRelativePath => "contract.yaml";

        public void Dispose()
        {
            try
            {
                if (Directory.Exists(ConfigRoot))
                {
                    Directory.Delete(ConfigRoot, recursive: true);
                }
            }
            catch (IOException)
            {
            }
        }
    }

    internal sealed class CountingRedactor : IRedactor
    {
        private IRedactor _inner;

        public CountingRedactor(IRedactor inner)
        {
            _inner = inner;
        }

        public int RedactObjectCalls { get; private set; }

        public string RedactText(string value, Domain.Policies.DisclosureProfile profile) =>
            _inner.RedactText(value, profile);

        public T RedactObject<T>(T value, Domain.Policies.DisclosureProfile profile)
        {
            RedactObjectCalls++;
            return _inner.RedactObject(value, profile);
        }
    }

    private sealed class CompositeDisposable(IReadOnlyList<IDisposable> items) : IDisposable
    {
        public void Dispose()
        {
            for (int i = items.Count - 1; i >= 0; i--)
            {
                items[i].Dispose();
            }
        }
    }
}
