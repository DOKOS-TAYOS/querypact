using System.Reflection;
using Sav.Application.Abstractions;
using Sav.Application.Attestations;
using Sav.Application.Migrations;
using Sav.Application.Tests.Analyze;
using Sav.Domain.Contracts;
using Sav.Domain.Decisions;
using Sav.Domain.Policies;
using Sav.Infrastructure.Storage.Attestations;

namespace Sav.Application.Tests.Migrations;

public sealed class VerifyMigrationUsesConfigPathResolverPortTests
{
    private static readonly byte[] Key = Enumerable.Repeat((byte)0x52, 32).ToArray();

    [Fact]
    public void Constructor_takes_IConfigPathResolver_not_infra_concrete()
    {
        ConstructorInfo ctor = typeof(VerifyMigrationUseCase).GetConstructors().Single();
        Type[] parameters = ctor.GetParameters().Select(p => p.ParameterType).ToArray();

        Assert.Contains(typeof(IConfigPathResolver), parameters);
        Assert.Contains(typeof(IShadowMigrationRunner), parameters);
        Assert.All(
            parameters,
            t => Assert.False(
                t.Namespace?.Contains("Infrastructure", StringComparison.OrdinalIgnoreCase) == true,
                $"Application must not depend on Infra type {t}"));
    }

    [Fact]
    public async Task Deny_path_resolves_policy_contract_and_base_schema_via_port()
    {
        RecordingPathResolver paths = new();
        RecordingShadow shadow = new();
        VerifyMigrationUseCase useCase = new(
            new FakeParser(success: false),
            new FakePolicyEngine(PolicyOutcome.Deny, ["sql_unparsable"]),
            new FakePolicyLoader(CreatePolicy()),
            new FakeContractLoader(CreateContract()),
            paths,
            shadow,
            new AttestationFactory(new AttestationHmac(), new RecordingRedactor()),
            new InMemoryStore(),
            new RecordingRedactor(),
            Key);

        _ = await useCase.ExecuteAsync(
            new VerifyMigrationRequest(
                MigrationSql: "NOT SQL",
                MigrationPath: null,
                BaseSchemaPath: "schemas/base.sql",
                PolicyPath: "policies/migration.yaml",
                ContractPath: "contracts/orphans.yaml"),
            CancellationToken.None);

        Assert.Equal(0, shadow.CallCount);
        Assert.Equal(3, paths.ResolveCalls);
        Assert.Contains("policies/migration.yaml", paths.Resolved);
        Assert.Contains("contracts/orphans.yaml", paths.Resolved);
        Assert.Contains("schemas/base.sql", paths.Resolved);
    }

    [Fact]
    public async Task MigrationPath_is_resolved_via_port_before_read()
    {
        using TempRoot root = TempRoot.CreateWithMigrationFile("CREATE INDEX orders_id_idx ON orders (id);");
        RecordingPathResolver paths = new(root.Path);
        RecordingShadow shadow = new();
        VerifyMigrationUseCase useCase = new(
            new FakeParser(success: false),
            new FakePolicyEngine(PolicyOutcome.Deny, ["sql_unparsable"]),
            new FakePolicyLoader(CreatePolicy()),
            new FakeContractLoader(CreateContract()),
            paths,
            shadow,
            new AttestationFactory(new AttestationHmac(), new RecordingRedactor()),
            new InMemoryStore(),
            new RecordingRedactor(),
            Key);

        _ = await useCase.ExecuteAsync(
            new VerifyMigrationRequest(
                MigrationSql: null,
                MigrationPath: "up.sql",
                BaseSchemaPath: "base.sql",
                PolicyPath: "policy.yaml",
                ContractPath: "contract.yaml"),
            CancellationToken.None);

        Assert.Contains("up.sql", paths.Resolved);
        Assert.Equal(0, shadow.CallCount);
    }

    private static Policy CreatePolicy() =>
        new(
            "p",
            "1",
            ["AlterTable"],
            [],
            [],
            [],
            false,
            true,
            true,
            "high",
            [],
            DisclosureProfileMerge.StrictDefaults());

    private static Contract CreateContract() =>
        new(
            "c",
            "1",
            [new SchemaInvariantSpec([new SchemaInvariantRequirement("orders", "r")])],
            DisclosureProfileMerge.StrictDefaults());

    private sealed class RecordingPathResolver : IConfigPathResolver
    {
        private readonly string? _root;

        public RecordingPathResolver(string? root = null)
        {
            _root = root;
        }

        public int ResolveCalls { get; private set; }

        public List<string> Resolved { get; } = [];

        public string ResolveUnderConfigRoot(string relativeOrConfiguredPath)
        {
            ResolveCalls++;
            Resolved.Add(relativeOrConfiguredPath);
            if (_root is null)
            {
                return Path.Combine("C:", "config", relativeOrConfiguredPath);
            }

            return Path.GetFullPath(Path.Combine(_root, relativeOrConfiguredPath));
        }
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
        public Task<string> SaveAsync(Domain.Attestations.Attestation attestation, CancellationToken cancellationToken) =>
            Task.FromResult(attestation.Id);

        public Task<Domain.Attestations.Attestation?> GetAsync(string attestationId, CancellationToken cancellationToken) =>
            Task.FromResult<Domain.Attestations.Attestation?>(null);
    }

    private sealed class TempRoot : IDisposable
    {
        private TempRoot(string path)
        {
            Path = path;
        }

        public string Path { get; }

        public static TempRoot CreateWithMigrationFile(string sql)
        {
            string root = System.IO.Path.Combine(
                System.IO.Path.GetTempPath(),
                "sav-m008b-path-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(root);
            File.WriteAllText(System.IO.Path.Combine(root, "up.sql"), sql);
            File.WriteAllText(System.IO.Path.Combine(root, "base.sql"), "SELECT 1");
            File.WriteAllText(System.IO.Path.Combine(root, "policy.yaml"), "x");
            File.WriteAllText(System.IO.Path.Combine(root, "contract.yaml"), "y");
            return new TempRoot(root);
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
