using System.Reflection;
using Microsoft.Extensions.DependencyInjection;
using Sav.Application.Abstractions;
using Sav.Application.Migrations;
using Sav.Domain.Decisions;
using Sav.Domain.Serialization;
using Sav.Domain.Targets;
using Sav.Host;
using Sav.Host.Cli;
using Sav.Host.Composition;
using Sav.Host.Configuration;
using Sav.Host.Mcp.Tools;
using Sav.Infrastructure.Storage.Attestations;

namespace Sav.Security.Tests.Surface;

/// <summary>
/// M009e: verify_migration never resolves or touches a real target alias (E2E / host DI).
/// </summary>
[Collection(SecurityEnvCollectionDefinition.Name)]
public sealed class VerifyMigrationNeverUsesRealAliasE2ETests
{
    [Fact]
    public async Task Host_di_allow_path_uses_ephemeral_fingerprint_and_never_resolves_aliases()
    {
        using MigrationRoot root = MigrationRoot.Create(includeRealAlias: true);
        (ServiceProvider sp, RecordingAliasResolver aliases) = BuildFullWithRecordingAliases(root);
        await using (sp)
        {
            IVerifyMigrationUseCase useCase = sp.GetRequiredService<IVerifyMigrationUseCase>();

            VerifyMigrationResponse response = await useCase.ExecuteAsync(
                new VerifyMigrationRequest(
                    MigrationSql: null,
                    MigrationPath: root.MigrationRelativePath,
                    BaseSchemaPath: root.BaseSchemaRelativePath,
                    PolicyPath: root.PolicyRelativePath,
                    ContractPath: root.ContractRelativePath),
                CancellationToken.None);

            Assert.Equal(AttestationDecision.Pass, response.Attestation.Decision);
            Assert.Equal(
                CanonicalJson.Sha256Hex(VerifyMigrationUseCase.EphemeralTargetFingerprintSeed),
                response.Attestation.TargetAliasFingerprint);
            Assert.Equal(0, aliases.ResolveCount);
            Assert.DoesNotContain(
                "Host=",
                CanonicalJson.Serialize(response),
                StringComparison.OrdinalIgnoreCase);
        }
    }

    [Fact]
    public void Request_cli_and_tool_surfaces_have_no_target_alias_hook()
    {
        Assert.Null(typeof(VerifyMigrationRequest).GetProperty("TargetAliasName"));
        Assert.Null(typeof(VerifyMigrationRequest).GetProperty("TargetAlias"));

        ConstructorInfo ctor = typeof(VerifyMigrationUseCase).GetConstructors().Single();
        Assert.DoesNotContain(
            ctor.GetParameters().Select(static p => p.ParameterType),
            static t => t == typeof(ITargetAliasResolver));

        MethodInfo tool = typeof(VerifyMigrationTool).GetMethod(nameof(VerifyMigrationTool.VerifyMigration))!;
        Assert.DoesNotContain(
            tool.GetParameters().Select(static p => p.Name),
            static n => n is not null && n.Contains("target", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(
            tool.GetParameters().Select(static p => p.Name),
            static n => n is not null && n.Contains("alias", StringComparison.OrdinalIgnoreCase));

        string? priorKey = Environment.GetEnvironmentVariable(AttestationHmacKeyDecoder.EnvironmentVariableName);
        try
        {
            Environment.SetEnvironmentVariable(
                AttestationHmacKeyDecoder.EnvironmentVariableName,
                "base64:" + Convert.ToBase64String(Enumerable.Repeat((byte)0x71, 32).ToArray()));

            using StringWriter stdout = new();
            using StringWriter stderr = new();
            Assert.Equal(0, Program.Run(["--mode", "Full", "verify-migration", "--help"], stdout, stderr));
            string help = stdout.ToString();
            Assert.DoesNotContain("--target", help, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("alias", help, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("ephemeral", help, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            Environment.SetEnvironmentVariable(AttestationHmacKeyDecoder.EnvironmentVariableName, priorKey);
        }

        // Command factory exists and is the Full-mode surface under test.
        Assert.NotNull(typeof(VerifyMigrationCommand).GetMethod(nameof(VerifyMigrationCommand.Create)));
    }

    private static (ServiceProvider Sp, RecordingAliasResolver Aliases) BuildFullWithRecordingAliases(
        MigrationRoot root)
    {
        ServiceCollection services = new();
        services.AddSavFull(FullOptions(root), root.HmacKey);
        ServiceDescriptor original = services.Single(d => d.ServiceType == typeof(ITargetAliasResolver));
        services.Remove(original);
        RecordingAliasResolver recorder = new();
        services.AddSingleton<ITargetAliasResolver>(recorder);
        ServiceProvider sp = services.BuildServiceProvider(new ServiceProviderOptions
        {
            ValidateOnBuild = true,
            ValidateScopes = true,
        });
        return (sp, recorder);
    }

    private static SavModeOptions FullOptions(MigrationRoot root) =>
        new()
        {
            Mode = DiProfile.Full,
            ConfigRoot = root.ConfigRoot,
            AttestationStoreRoot = root.StoreRoot,
            AliasToDsnEnvVar = new Dictionary<string, string>(root.AliasToDsnEnvVar, StringComparer.OrdinalIgnoreCase),
        };

    private sealed class RecordingAliasResolver : ITargetAliasResolver
    {
        public int ResolveCount { get; private set; }

        public TargetAlias Resolve(string aliasName)
        {
            ResolveCount++;
            throw new InvalidOperationException(
                "verify_migration must never resolve a real target alias; got: " + aliasName);
        }
    }

    private sealed class MigrationRoot : IDisposable
    {
        private MigrationRoot(
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

        public string BaseSchemaRelativePath => "base.sql";

        public string MigrationRelativePath => "migration.sql";

        public static MigrationRoot Create(bool includeRealAlias)
        {
            string root = Path.Combine(Path.GetTempPath(), "sav-mig-alias-" + Guid.NewGuid().ToString("N"));
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
            File.Copy(
                Path.Combine(fixtures, "migrations", "valid", "up.sql"),
                Path.Combine(root, "migration.sql"),
                overwrite: true);

            Dictionary<string, string> aliases = new(StringComparer.OrdinalIgnoreCase);
            if (includeRealAlias)
            {
                string env = "SAV_FAKE_REAL_ALIAS_" + Guid.NewGuid().ToString("N");
                Environment.SetEnvironmentVariable(
                    env,
                    "Host=127.0.0.1;Port=5432;Username=real;Password=must_not_touch;Database=real");
                aliases["real_prod"] = env;
                File.WriteAllText(
                    Path.Combine(root, SavModeOptions.TargetsFileName),
                    "{\"real_prod\":\"" + env + "\"}");
            }

            return new MigrationRoot(root, store, Enumerable.Repeat((byte)0x72, 32).ToArray(), aliases);
        }

        public void Dispose()
        {
            foreach (string env in AliasToDsnEnvVar.Values)
            {
                Environment.SetEnvironmentVariable(env, null);
            }

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
    }
}
