using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Sav.Application.Abstractions;
using Sav.Application.Migrations;
using Sav.Application.Verify;
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
/// Serializes Security tests that mutate process-wide SAV_* / HMAC environment variables
/// (CLI Program.Run paths). Shared by MVP-A and MVP-B egress surfaces.
/// </summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class SecurityEnvCollectionDefinition
{
    public const string Name = "SavSecurityEnv";
}

/// <summary>
/// M009e: every MVP-B verify_* egress path must pass through <see cref="IRedactor.RedactObject"/>
/// under real host DI (VerifyEquivalenceResponse / VerifyMigrationResponse + CLI + MCP).
/// Does not substitute for <see cref="AllEgressPathsRedactObjectMvpATests"/>.
/// </summary>
[Collection(SecurityEnvCollectionDefinition.Name)]
public sealed class AllEgressPathsRedactObjectVerifyHostTests
{
    private const string Canary = "CANARY_LITERAL_do_not_egress@example.invalid";

    [Fact]
    public async Task VerifyEquivalenceResponse_via_host_di_calls_RedactObject()
    {
        using EquivalenceRoot root = EquivalenceRoot.Create();
        (ServiceProvider sp, CountingRedactor counter) = BuildFullWithCounter(root.ConfigRoot, root.StoreRoot, root.HmacKey);
        await using (sp)
        {
            IVerifyEquivalenceUseCase useCase = sp.GetRequiredService<IVerifyEquivalenceUseCase>();
            int before = counter.RedactObjectCalls;

            VerifyEquivalenceResponse response = await useCase.ExecuteAsync(
                new VerifyEquivalenceRequest(
                    $"SELECT '{Canary}'",
                    "SELECT 1",
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
    public async Task VerifyMigrationResponse_via_host_di_calls_RedactObject()
    {
        using MigrationRoot root = MigrationRoot.Create();
        (ServiceProvider sp, CountingRedactor counter) = BuildFullWithCounter(root.ConfigRoot, root.StoreRoot, root.HmacKey);
        await using (sp)
        {
            IVerifyMigrationUseCase useCase = sp.GetRequiredService<IVerifyMigrationUseCase>();
            int before = counter.RedactObjectCalls;

            string deniedSql = File.ReadAllText(
                Path.Combine(FindRepoRoot(), "tests", "fixtures", "migrations", "denied", "copy.sql"));

            VerifyMigrationResponse response = await useCase.ExecuteAsync(
                new VerifyMigrationRequest(
                    MigrationSql: deniedSql + " -- " + Canary,
                    MigrationPath: null,
                    BaseSchemaPath: root.BaseSchemaRelativePath,
                    PolicyPath: root.PolicyRelativePath,
                    ContractPath: root.ContractRelativePath),
                CancellationToken.None);

            Assert.True(counter.RedactObjectCalls > before);
            Assert.True(
                response.Attestation.Decision is AttestationDecision.Deny or AttestationDecision.Review);
            AssertNoCanary(CanonicalJson.Serialize(response));
        }
    }

    [Fact]
    public void Cli_verify_equivalence_and_migration_stdout_json_are_redacted()
    {
        using EquivalenceRoot eqRoot = EquivalenceRoot.Create();
        using IDisposable eqEnv = ConfigureEnv(eqRoot.ConfigRoot, eqRoot.StoreRoot, eqRoot.HmacKey);

        using StringWriter eqOut = new();
        using StringWriter eqErr = new();
        int eqExit = Program.Run(
            [
                "--mode", "Full",
                "verify-equivalence",
                "--left-sql", $"SELECT '{Canary}'",
                "--right-sql", "SELECT 1",
                "--target", "missing_alias",
                "--policy", eqRoot.PolicyRelativePath,
                "--contract", eqRoot.ContractRelativePath,
            ],
            eqOut,
            eqErr);

        Assert.Equal(0, eqExit);
        string eqJson = eqOut.ToString();
        AssertNoCanary(eqJson);
        AssertNoConnectionStringLeak(eqJson);

        using MigrationRoot migRoot = MigrationRoot.Create();
        using IDisposable migEnv = ConfigureEnv(migRoot.ConfigRoot, migRoot.StoreRoot, migRoot.HmacKey);

        string deniedSql = File.ReadAllText(
            Path.Combine(FindRepoRoot(), "tests", "fixtures", "migrations", "denied", "create-extension.sql"));

        using StringWriter migOut = new();
        using StringWriter migErr = new();
        int migExit = Program.Run(
            [
                "--mode", "Full",
                "verify-migration",
                "--migration-sql", deniedSql + " -- " + Canary,
                "--base-schema", migRoot.BaseSchemaRelativePath,
                "--policy", migRoot.PolicyRelativePath,
                "--contract", migRoot.ContractRelativePath,
            ],
            migOut,
            migErr);

        Assert.Equal(0, migExit);
        string migJson = migOut.ToString();
        AssertNoCanary(migJson);
        AssertNoConnectionStringLeak(migJson);
    }

    [Fact]
    public async Task Mcp_verify_equivalence_and_migration_json_are_redacted()
    {
        using EquivalenceRoot eqRoot = EquivalenceRoot.Create();
        await using ServiceProvider eqSp = Program.BuildServiceProvider(
            DiProfile.Full,
            options: FullOptions(eqRoot.ConfigRoot, eqRoot.StoreRoot),
            hmacKey: eqRoot.HmacKey);
        {
            VerifyEquivalenceTool eqTool = new(eqSp.GetRequiredService<IVerifyEquivalenceUseCase>());
            string eqJson = await eqTool.VerifyEquivalence(
                $"SELECT '{Canary}'",
                "SELECT 1",
                "missing_alias",
                eqRoot.PolicyRelativePath,
                eqRoot.ContractRelativePath,
                CancellationToken.None);
            AssertNoCanary(eqJson);
            AssertNoConnectionStringLeak(eqJson);
            using JsonDocument eqDoc = JsonDocument.Parse(eqJson);
            Assert.Equal(
                (int)AttestationDecision.Deny,
                eqDoc.RootElement.GetProperty("attestation").GetProperty("decision").GetInt32());
        }

        using MigrationRoot migRoot = MigrationRoot.Create();
        await using ServiceProvider migSp = Program.BuildServiceProvider(
            DiProfile.Full,
            options: FullOptions(migRoot.ConfigRoot, migRoot.StoreRoot),
            hmacKey: migRoot.HmacKey);
        {
            VerifyMigrationTool migTool = new(migSp.GetRequiredService<IVerifyMigrationUseCase>());
            string deniedSql = File.ReadAllText(
                Path.Combine(FindRepoRoot(), "tests", "fixtures", "migrations", "denied", "multi-statement.sql"));
            string migJson = await migTool.VerifyMigration(
                migrationSql: deniedSql + " -- " + Canary,
                migrationPath: null,
                baseSchemaPath: migRoot.BaseSchemaRelativePath,
                policyPath: migRoot.PolicyRelativePath,
                contractPath: migRoot.ContractRelativePath,
                CancellationToken.None);
            AssertNoCanary(migJson);
            AssertNoConnectionStringLeak(migJson);
        }
    }

    private static (ServiceProvider Sp, CountingRedactor Counter) BuildFullWithCounter(
        string configRoot,
        string storeRoot,
        byte[] hmacKey)
    {
        ServiceCollection services = new();
        services.AddSavFull(FullOptions(configRoot, storeRoot), hmacKey);
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

    private static SavModeOptions FullOptions(string configRoot, string storeRoot) =>
        new()
        {
            Mode = DiProfile.Full,
            ConfigRoot = configRoot,
            AttestationStoreRoot = storeRoot,
        };

    private static IDisposable ConfigureEnv(string configRoot, string storeRoot, byte[] hmacKey)
    {
        string? priorMode = Environment.GetEnvironmentVariable(SavModeOptions.ModeEnvironmentVariable);
        string? priorConfig = Environment.GetEnvironmentVariable(SavModeOptions.ConfigRootEnvironmentVariable);
        string? priorStore = Environment.GetEnvironmentVariable(SavModeOptions.AttestationStoreRootEnvironmentVariable);
        string? priorKey = Environment.GetEnvironmentVariable(AttestationHmacKeyDecoder.EnvironmentVariableName);
        string? priorTargets = Environment.GetEnvironmentVariable(SavModeOptions.TargetsJsonEnvironmentVariable);

        Environment.SetEnvironmentVariable(SavModeOptions.ModeEnvironmentVariable, nameof(DiProfile.Full));
        Environment.SetEnvironmentVariable(SavModeOptions.ConfigRootEnvironmentVariable, configRoot);
        Environment.SetEnvironmentVariable(SavModeOptions.AttestationStoreRootEnvironmentVariable, storeRoot);
        Environment.SetEnvironmentVariable(SavModeOptions.TargetsJsonEnvironmentVariable, null);
        Environment.SetEnvironmentVariable(
            AttestationHmacKeyDecoder.EnvironmentVariableName,
            "base64:" + Convert.ToBase64String(hmacKey));

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

    private sealed class EquivalenceRoot : IDisposable
    {
        private EquivalenceRoot(string configRoot, string storeRoot, byte[] hmacKey)
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

        public static EquivalenceRoot Create()
        {
            string root = Path.Combine(Path.GetTempPath(), "sav-egress-eq-" + Guid.NewGuid().ToString("N"));
            string store = Path.Combine(root, "attestations");
            Directory.CreateDirectory(root);
            Directory.CreateDirectory(store);
            string fixtures = Path.Combine(FindRepoRoot(), "tests", "fixtures");
            File.Copy(
                Path.Combine(fixtures, "policies", "valid-basic.yaml"),
                Path.Combine(root, "policy.yaml"),
                overwrite: true);
            File.Copy(
                Path.Combine(fixtures, "contracts", "valid-mvp-b-equivalence.yaml"),
                Path.Combine(root, "contract.yaml"),
                overwrite: true);
            return new EquivalenceRoot(root, store, Enumerable.Repeat((byte)0xB1, 32).ToArray());
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

    private sealed class MigrationRoot : IDisposable
    {
        private MigrationRoot(string configRoot, string storeRoot, byte[] hmacKey)
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

        public string BaseSchemaRelativePath => "base.sql";

        public static MigrationRoot Create()
        {
            string root = Path.Combine(Path.GetTempPath(), "sav-egress-mig-" + Guid.NewGuid().ToString("N"));
            string store = Path.Combine(root, "attestations");
            Directory.CreateDirectory(root);
            Directory.CreateDirectory(store);
            string fixtures = Path.Combine(FindRepoRoot(), "tests", "fixtures");
            File.Copy(
                Path.Combine(fixtures, "policies", "migration-ddl.yaml"),
                Path.Combine(root, "policy.yaml"),
                overwrite: true);
            File.Copy(
                Path.Combine(fixtures, "contracts", "valid-mvp-b-schema-orphans.yaml"),
                Path.Combine(root, "contract.yaml"),
                overwrite: true);
            File.Copy(
                Path.Combine(fixtures, "migrations", "base", "schema.sql"),
                Path.Combine(root, "base.sql"),
                overwrite: true);
            return new MigrationRoot(root, store, Enumerable.Repeat((byte)0xB2, 32).ToArray());
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
