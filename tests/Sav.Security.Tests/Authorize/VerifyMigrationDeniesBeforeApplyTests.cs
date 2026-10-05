using Sav.Application.Abstractions;
using Sav.Application.Attestations;
using Sav.Application.Migrations;
using Sav.Domain.Attestations;
using Sav.Domain.Decisions;
using Sav.Infrastructure.Config;
using Sav.Infrastructure.Config.Paths;
using Sav.Infrastructure.Config.Policies;
using Sav.Infrastructure.Postgres.Parsing;
using Sav.Infrastructure.Postgres.Redaction;
using Sav.Infrastructure.Storage.Attestations;

namespace Sav.Security.Tests.Authorize;

public sealed class VerifyMigrationDeniesBeforeApplyTests
{
    private static readonly byte[] Key = Enumerable.Repeat((byte)0x61, 32).ToArray();

    [Theory]
    [InlineData("copy.sql")]
    [InlineData("create-extension.sql")]
    [InlineData("multi-statement.sql")]
    [InlineData("unparsable.sql")]
    [InlineData("denied-table.sql")]
    public async Task Denied_migration_fixtures_never_invoke_shadow(string fixtureFile)
    {
        using MigrationHarnessRoot root = MigrationHarnessRoot.Create();
        RecordingShadow shadow = new();
        VerifyMigrationUseCase useCase = CreateUseCase(root.Path, shadow);

        string sql = File.ReadAllText(
            Path.Combine(SecurityAnalyzeHarness.FindRepoRoot(), "tests", "fixtures", "migrations", "denied", fixtureFile));

        VerifyMigrationResponse response = await useCase.ExecuteAsync(
            new VerifyMigrationRequest(
                MigrationSql: sql,
                MigrationPath: null,
                BaseSchemaPath: "base.sql",
                PolicyPath: "policy.yaml",
                ContractPath: "contract.yaml"),
            CancellationToken.None);

        Assert.Equal(0, shadow.CallCount);
        Assert.True(
            response.Attestation.Decision is AttestationDecision.Deny or AttestationDecision.Review,
            $"Expected DENY/REVIEW for {fixtureFile}, got {response.Attestation.Decision}");
        Assert.DoesNotContain("password", response.AttestationId, StringComparison.OrdinalIgnoreCase);
    }

    private static VerifyMigrationUseCase CreateUseCase(string configRoot, IShadowMigrationRunner shadow)
    {
        ConfigPathResolver paths = new(new ConfigRootOptions { ConfigRoot = configRoot });
        return new VerifyMigrationUseCase(
            new LibPgQuerySqlParser(),
            new YamlPolicyEngine(),
            new YamlPolicyLoader(),
            new YamlContractLoader(),
            paths,
            shadow,
            new AttestationFactory(new AttestationHmac(), new StrictRedactor()),
            new InMemoryStore(),
            new StrictRedactor(),
            Key);
    }

    private sealed class RecordingShadow : IShadowMigrationRunner
    {
        public int CallCount { get; private set; }

        public Task<ShadowMigrationOutcome> RunAsync(
            ShadowMigrationCommand command,
            CancellationToken cancellationToken)
        {
            CallCount++;
            return Task.FromResult(new ShadowMigrationOutcome(true, true, [], null));
        }
    }

    private sealed class InMemoryStore : IAttestationStore
    {
        public Task<string> SaveAsync(Attestation attestation, CancellationToken cancellationToken) =>
            Task.FromResult(attestation.Id);

        public Task<Attestation?> GetAsync(string attestationId, CancellationToken cancellationToken) =>
            Task.FromResult<Attestation?>(null);
    }

    private sealed class MigrationHarnessRoot : IDisposable
    {
        private MigrationHarnessRoot(string path)
        {
            Path = path;
        }

        public string Path { get; }

        public static MigrationHarnessRoot Create()
        {
            string repo = SecurityAnalyzeHarness.FindRepoRoot();
            string root = System.IO.Path.Combine(
                System.IO.Path.GetTempPath(),
                "sav-m008b-deny-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(root);
            File.Copy(
                System.IO.Path.Combine(repo, "tests", "fixtures", "policies", "migration-ddl.yaml"),
                System.IO.Path.Combine(root, "policy.yaml"),
                overwrite: true);
            File.Copy(
                System.IO.Path.Combine(repo, "tests", "fixtures", "contracts", "valid-mvp-b-schema-orphans.yaml"),
                System.IO.Path.Combine(root, "contract.yaml"),
                overwrite: true);
            File.Copy(
                System.IO.Path.Combine(repo, "tests", "fixtures", "migrations", "base", "schema.sql"),
                System.IO.Path.Combine(root, "base.sql"),
                overwrite: true);
            return new MigrationHarnessRoot(root);
        }

        public void Dispose()
        {
            try
            {
                if (Directory.Exists(Path))
                {
                    Directory.Delete(Path, recursive: true);
                }
            }
            catch (IOException)
            {
            }
        }
    }
}
