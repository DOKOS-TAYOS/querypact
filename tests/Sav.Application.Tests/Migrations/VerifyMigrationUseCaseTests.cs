using Sav.Application.Abstractions;
using Sav.Application.Attestations;
using Sav.Application.Migrations;
using Sav.Application.Tests.Analyze;
using Sav.Domain.Attestations;
using Sav.Domain.Contracts;
using Sav.Domain.Decisions;
using Sav.Domain.Errors;
using Sav.Domain.Policies;
using Sav.Domain.Properties;
using Sav.Infrastructure.Storage.Attestations;

namespace Sav.Application.Tests.Migrations;

public sealed class VerifyMigrationUseCaseTests
{
    private static readonly byte[] Key = Enumerable.Repeat((byte)0x51, 32).ToArray();

    [Fact]
    public async Task Deny_unparsable_never_calls_shadow_and_attests_deny()
    {
        RecordingShadow shadow = new();
        FakeStore store = new();
        VerifyMigrationUseCase useCase = CreateUseCase(
            new FakeParser(success: false),
            new FakePolicyEngine(PolicyOutcome.Deny, ["sql_unparsable"]),
            shadow,
            store);

        VerifyMigrationResponse response = await useCase.ExecuteAsync(
            ValidRequest(),
            CancellationToken.None);

        Assert.Equal(0, shadow.CallCount);
        Assert.Equal(AttestationDecision.Deny, response.Attestation.Decision);
        Assert.Equal(response.AttestationId, response.Attestation.Id);
        Assert.True(store.Saved.ContainsKey(response.AttestationId));
    }

    [Fact]
    public async Task Deny_policy_never_calls_shadow()
    {
        RecordingShadow shadow = new();
        VerifyMigrationUseCase useCase = CreateUseCase(
            new FakeParser(success: true),
            new FakePolicyEngine(PolicyOutcome.Deny, ["forbidden_statement_type"]),
            shadow,
            new FakeStore());

        VerifyMigrationResponse response = await useCase.ExecuteAsync(
            ValidRequest(),
            CancellationToken.None);

        Assert.Equal(0, shadow.CallCount);
        Assert.Equal(AttestationDecision.Deny, response.Attestation.Decision);
    }

    [Fact]
    public async Task Allow_calls_shadow_once_and_attests_pass_when_properties_pass()
    {
        using TempMigrationRoot root = TempMigrationRoot.Create();
        RecordingShadow shadow = new(applied: true, propertyStatus: PropertyStatus.Pass);
        FakeStore store = new();
        VerifyMigrationUseCase useCase = CreateUseCase(
            new FakeParser(success: true),
            new FakePolicyEngine(PolicyOutcome.Allow),
            shadow,
            store,
            new RootPathResolver(root.Path),
            new FakePolicyLoader(MigrationPolicy()),
            new FakeContractLoader(MigrationContract()));

        VerifyMigrationResponse response = await useCase.ExecuteAsync(
            new VerifyMigrationRequest(
                MigrationSql: "CREATE INDEX orders_id_idx ON orders (id)",
                MigrationPath: null,
                BaseSchemaPath: "base.sql",
                PolicyPath: "policy.yaml",
                ContractPath: "contract.yaml"),
            CancellationToken.None);

        Assert.Equal(1, shadow.CallCount);
        Assert.Equal(AttestationDecision.Pass, response.Attestation.Decision);
        Assert.All(response.Attestation.Properties, p => Assert.Equal(PropertyStatus.Pass, p.Status));
        Assert.Equal(
            CanonicalEphemeralFingerprint(),
            response.Attestation.TargetAliasFingerprint);
    }

    [Fact]
    public async Task Xor_migration_args_rejects_both_or_neither()
    {
        // Fail-closed with attestation (no untyped throw to MCP/CLI callers).
        FakeStore store = new();
        VerifyMigrationUseCase useCase = CreateUseCase(
            new FakeParser(success: true),
            new FakePolicyEngine(PolicyOutcome.Allow),
            new RecordingShadow(),
            store);

        VerifyMigrationResponse neither = await useCase.ExecuteAsync(
            new VerifyMigrationRequest(null, null, "base.sql", "policy.yaml", "contract.yaml"),
            CancellationToken.None);
        Assert.Equal(AttestationDecision.Deny, neither.Attestation.Decision);
        Assert.True(store.Saved.ContainsKey(neither.AttestationId));

        VerifyMigrationResponse both = await useCase.ExecuteAsync(
            new VerifyMigrationRequest(
                "ALTER TABLE orders ADD COLUMN x int",
                "mig.sql",
                "base.sql",
                "policy.yaml",
                "contract.yaml"),
            CancellationToken.None);
        Assert.Equal(AttestationDecision.Deny, both.Attestation.Decision);
        Assert.True(store.Saved.ContainsKey(both.AttestationId));
    }

    [Fact]
    public async Task Shadow_apply_failure_persists_redacted_error_on_property_detail()
    {
        using TempMigrationRoot root = TempMigrationRoot.Create();
        RecordingShadow shadow = new(applied: false, redactedError: "query_failed");
        FakeStore store = new();
        VerifyMigrationUseCase useCase = CreateUseCase(
            new FakeParser(success: true),
            new FakePolicyEngine(PolicyOutcome.Allow),
            shadow,
            store,
            new RootPathResolver(root.Path),
            new FakePolicyLoader(MigrationPolicy()),
            new FakeContractLoader(MigrationContract()));

        VerifyMigrationResponse response = await useCase.ExecuteAsync(
            new VerifyMigrationRequest(
                MigrationSql: "CREATE INDEX orders_id_idx ON orders (id)",
                MigrationPath: null,
                BaseSchemaPath: "base.sql",
                PolicyPath: "policy.yaml",
                ContractPath: "contract.yaml"),
            CancellationToken.None);

        Assert.Equal(AttestationDecision.Fail, response.Attestation.Decision);
        PropertyResult apply = Assert.Single(response.Attestation.Properties);
        Assert.Equal("shadow_apply", apply.Name);
        Assert.Equal(PropertyStatus.Fail, apply.Status);
        Assert.Equal("query_failed", apply.RedactedDetail);
        Assert.DoesNotContain("Host=", apply.RedactedDetail!, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("password", apply.RedactedDetail!, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Shadow_apply_failure_with_dsn_like_error_coerces_to_query_failed()
    {
        using TempMigrationRoot root = TempMigrationRoot.Create();
        RecordingShadow shadow = new(
            applied: false,
            redactedError: "Host=evil.example;Password=super-secret-password");
        VerifyMigrationUseCase useCase = CreateUseCase(
            new FakeParser(success: true),
            new FakePolicyEngine(PolicyOutcome.Allow),
            shadow,
            new FakeStore(),
            new RootPathResolver(root.Path),
            new FakePolicyLoader(MigrationPolicy()),
            new FakeContractLoader(MigrationContract()));

        VerifyMigrationResponse response = await useCase.ExecuteAsync(
            new VerifyMigrationRequest(
                MigrationSql: "CREATE INDEX orders_id_idx ON orders (id)",
                MigrationPath: null,
                BaseSchemaPath: "base.sql",
                PolicyPath: "policy.yaml",
                ContractPath: "contract.yaml"),
            CancellationToken.None);

        PropertyResult apply = Assert.Single(response.Attestation.Properties);
        Assert.Equal(SavErrorCode.QueryFailed, apply.RedactedDetail);
    }

    [Theory]
    [InlineData("relation \"secret_orders\" does not exist")]
    [InlineData("violates foreign key constraint \"order_items_order_id_fkey\"")]
    [InlineData("syntax error at or near \"CRETE\"")]
    [InlineData("column \"ssn\" of relation \"people\" does not exist")]
    public async Task Shadow_apply_pg_like_free_text_coerces_to_query_failed(string pgLikeError)
    {
        using TempMigrationRoot root = TempMigrationRoot.Create();
        RecordingShadow shadow = new(applied: false, redactedError: pgLikeError);
        VerifyMigrationUseCase useCase = CreateUseCase(
            new FakeParser(success: true),
            new FakePolicyEngine(PolicyOutcome.Allow),
            shadow,
            new FakeStore(),
            new RootPathResolver(root.Path),
            new FakePolicyLoader(MigrationPolicy()),
            new FakeContractLoader(MigrationContract()));

        VerifyMigrationResponse response = await useCase.ExecuteAsync(
            new VerifyMigrationRequest(
                MigrationSql: "CREATE INDEX orders_id_idx ON orders (id)",
                MigrationPath: null,
                BaseSchemaPath: "base.sql",
                PolicyPath: "policy.yaml",
                ContractPath: "contract.yaml"),
            CancellationToken.None);

        PropertyResult apply = Assert.Single(response.Attestation.Properties);
        Assert.Equal(SavErrorCode.QueryFailed, apply.RedactedDetail);
        Assert.DoesNotContain("secret_orders", apply.RedactedDetail!, StringComparison.Ordinal);
        Assert.DoesNotContain("order_items", apply.RedactedDetail!, StringComparison.Ordinal);
        Assert.DoesNotContain("CRETE", apply.RedactedDetail!, StringComparison.Ordinal);
        Assert.DoesNotContain("ssn", apply.RedactedDetail!, StringComparison.Ordinal);
        Assert.DoesNotContain("people", apply.RedactedDetail!, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Shadow_apply_known_fixed_code_is_preserved()
    {
        using TempMigrationRoot root = TempMigrationRoot.Create();
        RecordingShadow shadow = new(applied: false, redactedError: SavErrorCode.SchemaInvariantFailed);
        VerifyMigrationUseCase useCase = CreateUseCase(
            new FakeParser(success: true),
            new FakePolicyEngine(PolicyOutcome.Allow),
            shadow,
            new FakeStore(),
            new RootPathResolver(root.Path),
            new FakePolicyLoader(MigrationPolicy()),
            new FakeContractLoader(MigrationContract()));

        VerifyMigrationResponse response = await useCase.ExecuteAsync(
            new VerifyMigrationRequest(
                MigrationSql: "CREATE INDEX orders_id_idx ON orders (id)",
                MigrationPath: null,
                BaseSchemaPath: "base.sql",
                PolicyPath: "policy.yaml",
                ContractPath: "contract.yaml"),
            CancellationToken.None);

        PropertyResult apply = Assert.Single(response.Attestation.Properties);
        Assert.Equal(SavErrorCode.SchemaInvariantFailed, apply.RedactedDetail);
    }

    [Theory]
    [InlineData(null, null)]
    [InlineData("CREATE INDEX x ON t(id)", "mig.sql")]
    public async Task Both_or_neither_migration_inputs_return_attestation_not_throw(
        string? migrationSql,
        string? migrationPath)
    {
        FakeStore store = new();
        VerifyMigrationUseCase useCase = CreateUseCase(
            new FakeParser(success: true),
            new FakePolicyEngine(PolicyOutcome.Allow),
            new RecordingShadow(),
            store);

        VerifyMigrationResponse response = await useCase.ExecuteAsync(
            new VerifyMigrationRequest(
                MigrationSql: migrationSql,
                MigrationPath: migrationPath,
                BaseSchemaPath: "base.sql",
                PolicyPath: "policy.yaml",
                ContractPath: "contract.yaml"),
            CancellationToken.None);

        Assert.NotNull(response.Attestation);
        Assert.Equal(AttestationDecision.Deny, response.Attestation.Decision);
        Assert.True(store.Saved.ContainsKey(response.AttestationId));
        Assert.Contains(
            response.Attestation.Properties,
            p => p.RedactedDetail == SavErrorCode.UnsupportedConstruct);
    }

    private static VerifyMigrationUseCase CreateUseCase(
        ISqlParser parser,
        IPolicyEngine engine,
        IShadowMigrationRunner shadow,
        IAttestationStore store,
        IConfigPathResolver? paths = null,
        IPolicyLoader? policies = null,
        IContractLoader? contracts = null)
    {
        return new VerifyMigrationUseCase(
            parser,
            engine,
            policies ?? new FakePolicyLoader(MigrationPolicy()),
            contracts ?? new FakeContractLoader(MigrationContract()),
            paths ?? new FakePathResolver(),
            shadow,
            new AttestationFactory(new AttestationHmac(), new RecordingRedactor()),
            store,
            new RecordingRedactor(),
            Key);
    }

    private static VerifyMigrationRequest ValidRequest() =>
        new(
            MigrationSql: "CREATE INDEX orders_id_idx ON orders (id)",
            MigrationPath: null,
            BaseSchemaPath: "base.sql",
            PolicyPath: "policy.yaml",
            ContractPath: "contract.yaml");

    private static Policy MigrationPolicy() =>
        new(
            id: "migration-ddl",
            version: "1",
            allowedStatementTypes: ["AlterTable", "IndexStmt", "CreateTable"],
            deniedTables: ["secret_table"],
            deniedColumns: [],
            allowedFunctions: [],
            denyUnresolvedObjects: false,
            denyMultipleStatements: true,
            denyUpdateDeleteWithoutPredicate: true,
            maxCostBucket: "high",
            forbiddenPlanNodes: [],
            disclosure: DisclosureProfileMerge.StrictDefaults());

    private static Contract MigrationContract() =>
        new(
            "mvp-b-schema-orphans",
            "1",
            [
                new SchemaInvariantSpec(
                [
                    new SchemaInvariantRequirement("orders", "r"),
                    new SchemaInvariantRequirement("order_items", "r"),
                ]),
                new NoNewOrphansSpec("orders", "id", "order_items", "order_id"),
            ],
            DisclosureProfileMerge.StrictDefaults());

    private static string CanonicalEphemeralFingerprint() =>
        Sav.Domain.Serialization.CanonicalJson.Sha256Hex(
            VerifyMigrationUseCase.EphemeralTargetFingerprintSeed);

    private sealed class RecordingShadow : IShadowMigrationRunner
    {
        private readonly bool _applied;
        private readonly PropertyStatus _status;
        private readonly string? _redactedError;

        public RecordingShadow(
            bool applied = true,
            PropertyStatus propertyStatus = PropertyStatus.Pass,
            string? redactedError = "query_failed")
        {
            _applied = applied;
            _status = propertyStatus;
            _redactedError = redactedError;
        }

        public int CallCount { get; private set; }

        public Task<ShadowMigrationOutcome> RunAsync(
            ShadowMigrationCommand command,
            CancellationToken cancellationToken)
        {
            CallCount++;
            IReadOnlyList<PropertyResult> properties = _applied
                ?
                [
                    new PropertyResult("schema_invariant", _status, null),
                    new PropertyResult("no_new_orphans", _status, null),
                ]
                : [];
            return Task.FromResult(new ShadowMigrationOutcome(
                _applied,
                ContainerDestroyed: true,
                properties,
                RedactedError: _applied ? null : _redactedError));
        }
    }

    private sealed class FakeStore : IAttestationStore
    {
        public Dictionary<string, Attestation> Saved { get; } = new(StringComparer.Ordinal);

        public Task<string> SaveAsync(Attestation attestation, CancellationToken cancellationToken)
        {
            Saved[attestation.Id] = attestation;
            return Task.FromResult(attestation.Id);
        }

        public Task<Attestation?> GetAsync(string attestationId, CancellationToken cancellationToken) =>
            Task.FromResult(Saved.TryGetValue(attestationId, out Attestation? a) ? a : null);
    }

    private sealed class RootPathResolver : IConfigPathResolver
    {
        private readonly string _root;

        public RootPathResolver(string root)
        {
            _root = root;
        }

        public string ResolveUnderConfigRoot(string relativeOrConfiguredPath) =>
            Path.GetFullPath(Path.Combine(_root, relativeOrConfiguredPath));
    }

    private sealed class TempMigrationRoot : IDisposable
    {
        private TempMigrationRoot(string path)
        {
            Path = path;
        }

        public string Path { get; }

        public static TempMigrationRoot Create()
        {
            string root = System.IO.Path.Combine(
                System.IO.Path.GetTempPath(),
                "sav-m008b-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(root);
            File.WriteAllText(System.IO.Path.Combine(root, "base.sql"), "SELECT 1;");
            File.WriteAllText(System.IO.Path.Combine(root, "policy.yaml"), "id: x");
            File.WriteAllText(System.IO.Path.Combine(root, "contract.yaml"), "id: y");
            return new TempMigrationRoot(root);
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
