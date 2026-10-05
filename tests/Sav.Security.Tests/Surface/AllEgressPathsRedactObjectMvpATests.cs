using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Sav.Application.Abstractions;
using Sav.Application.Analyze;
using Sav.Application.Verify;
using Sav.Domain.Attestations;
using Sav.Domain.Decisions;
using Sav.Domain.Policies;
using Sav.Domain.Serialization;
using Sav.Host;
using Sav.Host.Composition;
using Sav.Host.Configuration;
using Sav.Host.Mcp.Tools;
using Sav.Infrastructure.Postgres.Redaction;
using Sav.Infrastructure.Storage.Attestations;

namespace Sav.Security.Tests.Surface;

/// <summary>
/// M009d: every MVP-A egress path must pass through <see cref="IRedactor.RedactObject"/>
/// under real host DI (analyze / verify_query / get_attestation + CLI + MCP).
/// Does not cover verify_equivalence / verify_migration (M009e).
/// </summary>
[Collection(SecurityEnvCollectionDefinition.Name)]
public sealed class AllEgressPathsRedactObjectMvpATests
{
    private const string Canary = "CANARY_LITERAL_do_not_egress@example.invalid";

    [Fact]
    public async Task AnalyzeSqlResponse_via_host_di_calls_RedactObject()
    {
        using TempRoot root = TempRoot.Create(includeContract: false);
        (ServiceProvider sp, CountingRedactor counter) = BuildAnalyzeOnlyWithCounter(root);
        await using (sp)
        {
            IAnalyzeSqlUseCase useCase = sp.GetRequiredService<IAnalyzeSqlUseCase>();
            int before = counter.RedactObjectCalls;

            AnalyzeSqlResponse response = await useCase.ExecuteAsync(
                new AnalyzeSqlRequest(
                    $"SELECT id FROM users WHERE note = '{Canary}'",
                    root.PolicyRelativePath,
                    null),
                CancellationToken.None);

            Assert.True(counter.RedactObjectCalls > before);
            string json = CanonicalJson.Serialize(response);
            AssertNoCanary(json);
            Assert.DoesNotContain("users", string.Join('|', response.Analysis.Ir.TablesRead), StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task VerifyQueryResponse_via_host_di_calls_RedactObject()
    {
        using TempRoot root = TempRoot.Create();
        (ServiceProvider sp, CountingRedactor counter) = BuildFullWithCounter(root);
        await using (sp)
        {
            IVerifyQueryUseCase useCase = sp.GetRequiredService<IVerifyQueryUseCase>();
            int before = counter.RedactObjectCalls;

            VerifyQueryResponse response = await useCase.ExecuteAsync(
                new VerifyQueryRequest(
                    $"SELECT '{Canary}'",
                    "missing_alias",
                    root.PolicyRelativePath,
                    root.ContractRelativePath),
                CancellationToken.None);

            Assert.True(counter.RedactObjectCalls > before);
            Assert.Equal(AttestationDecision.Deny, response.Attestation.Decision);
            AssertNoCanary(CanonicalJson.Serialize(response));
        }
    }

    [Fact]
    public async Task GetAttestation_via_host_di_calls_RedactObject()
    {
        using TempRoot root = TempRoot.Create();
        (ServiceProvider sp, CountingRedactor counter) = BuildFullWithCounter(root);
        await using (sp)
        {
            IVerifyQueryUseCase verify = sp.GetRequiredService<IVerifyQueryUseCase>();
            IGetAttestationUseCase get = sp.GetRequiredService<IGetAttestationUseCase>();

            VerifyQueryResponse created = await verify.ExecuteAsync(
                new VerifyQueryRequest(
                    "NOT VALID SQL !!!",
                    "missing_alias",
                    root.PolicyRelativePath,
                    root.ContractRelativePath),
                CancellationToken.None);

            int before = counter.RedactObjectCalls;
            Attestation? loaded = await get.ExecuteAsync(created.AttestationId, CancellationToken.None);
            Assert.NotNull(loaded);
            Assert.True(counter.RedactObjectCalls > before);
            AssertNoCanary(CanonicalJson.Serialize(loaded));
        }
    }

    [Fact]
    public void Cli_analyze_stdout_json_is_redacted()
    {
        using TempRoot root = TempRoot.Create(includeContract: false);
        using IDisposable env = ConfigureEnv(root, DiProfile.AnalyzeOnly);

        using StringWriter stdout = new();
        using StringWriter stderr = new();
        int exit = Program.Run(
            [
                "--mode", "AnalyzeOnly",
                "analyze",
                "--sql", $"SELECT id FROM secrets WHERE note = '{Canary}'",
                "--policy", root.PolicyRelativePath,
            ],
            stdout,
            stderr);

        Assert.Equal(0, exit);
        string json = stdout.ToString();
        AssertNoCanary(json);
        AssertNoConnectionStringLeak(json);
        using JsonDocument doc = JsonDocument.Parse(json.Trim());
        Assert.Equal(
            (int)PolicyOutcome.Deny,
            doc.RootElement.GetProperty("decision").GetProperty("outcome").GetInt32());
    }

    [Fact]
    public void Cli_verify_query_and_attestation_get_stdout_json_are_redacted()
    {
        using TempRoot root = TempRoot.Create();
        using IDisposable env = ConfigureEnv(root, DiProfile.Full);

        using StringWriter verifyOut = new();
        using StringWriter verifyErr = new();
        int verifyExit = Program.Run(
            [
                "--mode", "Full",
                "verify-query",
                "--sql", $"SELECT '{Canary}'",
                "--target", "missing_alias",
                "--policy", root.PolicyRelativePath,
                "--contract", root.ContractRelativePath,
            ],
            verifyOut,
            verifyErr);

        Assert.Equal(0, verifyExit);
        string verifyJson = verifyOut.ToString();
        AssertNoCanary(verifyJson);
        AssertNoConnectionStringLeak(verifyJson);

        using JsonDocument verifyDoc = JsonDocument.Parse(verifyJson.Trim());
        string id = verifyDoc.RootElement.GetProperty("attestationId").GetString()!;

        using StringWriter getOut = new();
        using StringWriter getErr = new();
        int getExit = Program.Run(
            ["--mode", "Full", "attestation", "get", "--id", id],
            getOut,
            getErr);

        Assert.Equal(0, getExit);
        string getJson = getOut.ToString();
        AssertNoCanary(getJson);
        AssertNoConnectionStringLeak(getJson);
    }

    [Fact]
    public async Task Mcp_analyze_verify_and_get_json_are_redacted()
    {
        using TempRoot root = TempRoot.Create();
        await using ServiceProvider sp = Program.BuildServiceProvider(
            DiProfile.Full,
            options: FullOptions(root),
            hmacKey: root.HmacKey);
        {
            AnalyzeSqlTool analyze = new(sp.GetRequiredService<IAnalyzeSqlUseCase>());
            VerifyQueryTool verify = new(sp.GetRequiredService<IVerifyQueryUseCase>());
            GetAttestationTool get = new(sp.GetRequiredService<IGetAttestationUseCase>());

            string analyzeJson = await analyze.AnalyzeSql(
                $"SELECT id FROM secrets WHERE note = '{Canary}'",
                root.PolicyRelativePath,
                null,
                CancellationToken.None);
            AssertNoCanary(analyzeJson);

            string verifyJson = await verify.VerifyQuery(
                $"SELECT '{Canary}'",
                "missing_alias",
                root.PolicyRelativePath,
                root.ContractRelativePath,
                CancellationToken.None);
            AssertNoCanary(verifyJson);

            using JsonDocument verifyDoc = JsonDocument.Parse(verifyJson);
            string id = verifyDoc.RootElement.GetProperty("attestationId").GetString()!;

            string getJson = await get.GetAttestation(id, CancellationToken.None);
            AssertNoCanary(getJson);
            AssertNoConnectionStringLeak(analyzeJson + verifyJson + getJson);
        }
    }

    private static (ServiceProvider Sp, CountingRedactor Counter) BuildAnalyzeOnlyWithCounter(TempRoot root)
    {
        ServiceCollection services = new();
        services.AddSavAnalyzeOnly(AnalyzeOnlyOptions(root));
        WrapRedactor(services);
        ServiceProvider sp = services.BuildServiceProvider(new ServiceProviderOptions
        {
            ValidateOnBuild = true,
            ValidateScopes = true,
        });
        CountingRedactor counter = (CountingRedactor)sp.GetRequiredService<IRedactor>();
        return (sp, counter);
    }

    private static (ServiceProvider Sp, CountingRedactor Counter) BuildFullWithCounter(TempRoot root)
    {
        ServiceCollection services = new();
        services.AddSavFull(FullOptions(root), root.HmacKey);
        WrapRedactor(services);
        ServiceProvider sp = services.BuildServiceProvider(new ServiceProviderOptions
        {
            ValidateOnBuild = true,
            ValidateScopes = true,
        });
        CountingRedactor counter = (CountingRedactor)sp.GetRequiredService<IRedactor>();
        return (sp, counter);
    }

    private static void WrapRedactor(IServiceCollection services)
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

            IRedactor inner;
            if (original.ImplementationFactory is not null)
            {
                inner = (IRedactor)original.ImplementationFactory(sp)!;
            }
            else if (original.ImplementationInstance is IRedactor instance)
            {
                inner = instance;
            }
            else
            {
                inner = new PostgresErrorRedactor(sp.GetRequiredService<StrictRedactor>());
            }

            holder = new CountingRedactor(inner);
            return holder;
        });
    }

    private static SavModeOptions AnalyzeOnlyOptions(TempRoot root) =>
        new()
        {
            Mode = DiProfile.AnalyzeOnly,
            ConfigRoot = root.ConfigRoot,
            AttestationStoreRoot = root.StoreRoot,
        };

    private static SavModeOptions FullOptions(TempRoot root) =>
        new()
        {
            Mode = DiProfile.Full,
            ConfigRoot = root.ConfigRoot,
            AttestationStoreRoot = root.StoreRoot,
        };

    private static IDisposable ConfigureEnv(TempRoot root, DiProfile mode)
    {
        string? priorMode = Environment.GetEnvironmentVariable(SavModeOptions.ModeEnvironmentVariable);
        string? priorConfig = Environment.GetEnvironmentVariable(SavModeOptions.ConfigRootEnvironmentVariable);
        string? priorStore = Environment.GetEnvironmentVariable(SavModeOptions.AttestationStoreRootEnvironmentVariable);
        string? priorKey = Environment.GetEnvironmentVariable(AttestationHmacKeyDecoder.EnvironmentVariableName);
        string? priorTargets = Environment.GetEnvironmentVariable(SavModeOptions.TargetsJsonEnvironmentVariable);

        Environment.SetEnvironmentVariable(
            SavModeOptions.ModeEnvironmentVariable,
            mode == DiProfile.AnalyzeOnly ? nameof(DiProfile.AnalyzeOnly) : nameof(DiProfile.Full));
        Environment.SetEnvironmentVariable(SavModeOptions.ConfigRootEnvironmentVariable, root.ConfigRoot);
        Environment.SetEnvironmentVariable(SavModeOptions.AttestationStoreRootEnvironmentVariable, root.StoreRoot);
        Environment.SetEnvironmentVariable(SavModeOptions.TargetsJsonEnvironmentVariable, null);
        if (mode == DiProfile.Full)
        {
            Environment.SetEnvironmentVariable(
                AttestationHmacKeyDecoder.EnvironmentVariableName,
                "base64:" + Convert.ToBase64String(root.HmacKey));
        }

        return new RestoreEnv(priorMode, priorConfig, priorStore, priorKey, priorTargets);
    }

    private static void AssertNoCanary(string text) =>
        Assert.DoesNotContain(Canary, text, StringComparison.OrdinalIgnoreCase);

    private static void AssertNoConnectionStringLeak(string text)
    {
        foreach (string pattern in new[] { "Host=", "Password=", "Username=", "postgres://", "postgresql://" })
        {
            Assert.DoesNotContain(pattern, text, StringComparison.OrdinalIgnoreCase);
        }
    }

    private static string FindRepoRoot()
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

        throw new InvalidOperationException("QueryPact.sln not found.");
    }

    private sealed class CountingRedactor : IRedactor
    {
        private readonly IRedactor _inner;

        public CountingRedactor(IRedactor inner) => _inner = inner;

        public int RedactObjectCalls { get; private set; }

        public string RedactText(string value, DisclosureProfile profile) =>
            _inner.RedactText(value, profile);

        public T RedactObject<T>(T value, DisclosureProfile profile)
        {
            RedactObjectCalls++;
            return _inner.RedactObject(value, profile);
        }
    }

    private sealed class TempRoot : IDisposable
    {
        private TempRoot(string configRoot, string storeRoot, byte[] hmacKey)
        {
            ConfigRoot = configRoot;
            StoreRoot = storeRoot;
            HmacKey = hmacKey;
        }

        public string ConfigRoot { get; }

        public string StoreRoot { get; }

        public byte[] HmacKey { get; }

        public string PolicyRelativePath => "policy.yaml";

        public string ContractRelativePath => "contract.yaml";

        public static TempRoot Create(bool includeContract = true)
        {
            string root = Path.Combine(Path.GetTempPath(), "sav-egress-" + Guid.NewGuid().ToString("N"));
            string store = Path.Combine(root, "attestations");
            Directory.CreateDirectory(root);
            Directory.CreateDirectory(store);
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

            return new TempRoot(root, store, Enumerable.Repeat((byte)0xA9, 32).ToArray());
        }

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

    private sealed class RestoreEnv(
        string? mode,
        string? config,
        string? store,
        string? key,
        string? targets) : IDisposable
    {
        public void Dispose()
        {
            Environment.SetEnvironmentVariable(SavModeOptions.ModeEnvironmentVariable, mode);
            Environment.SetEnvironmentVariable(SavModeOptions.ConfigRootEnvironmentVariable, config);
            Environment.SetEnvironmentVariable(SavModeOptions.AttestationStoreRootEnvironmentVariable, store);
            Environment.SetEnvironmentVariable(AttestationHmacKeyDecoder.EnvironmentVariableName, key);
            Environment.SetEnvironmentVariable(SavModeOptions.TargetsJsonEnvironmentVariable, targets);
        }
    }
}
