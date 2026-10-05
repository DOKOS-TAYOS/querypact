using Sav.Application.Abstractions;
using Sav.Application.Attestations;
using Sav.Application.Verify;
using Sav.Domain.Analysis;
using Sav.Domain.Attestations;
using Sav.Domain.Contracts;
using Sav.Domain.Decisions;
using Sav.Domain.Policies;
using Sav.Domain.Properties;
using Sav.Domain.Targets;
using Sav.Infrastructure.Config.Policies;
using Sav.Infrastructure.Storage.Attestations;

namespace Sav.Application.Tests.Verify;

public sealed class DenyUnresolvedDeferredUntilCatalogTests
{
    private static readonly byte[] HmacKey = Enumerable.Repeat((byte)0x4d, 32).ToArray();

    [Fact]
    public async Task Verify_query_resolvable_object_reaches_catalog_and_is_allowed()
    {
        RecordingSessionFactory sessions = new();
        RecordingCatalog catalog = new();
        RecordingPlanProvider plan = new();
        RecordingOracle oracle = new();
        RecordingGuard guard = new();

        VerificationPipeline pipeline = new(
            new UnresolvedParser("resolved_users"),
            new YamlPolicyEngine(),
            new DenyUnresolvedPolicyLoader(),
            new FixedContractLoader(),
            new FixedPathResolver(),
            new FixedAliasResolver(),
            sessions,
            catalog,
            plan,
            oracle,
            guard,
            new PipelineRecordingRedactor());

        VerificationPipelineResult result = await pipeline.ExecuteAsync(
            new VerifyQueryRequest(
                "SELECT id FROM resolved_users",
                "demo",
                "p.yaml",
                "c.yaml"),
            CancellationToken.None);

        Assert.Equal(AttestationDecision.Pass, result.Decision);
        Assert.Equal(1, sessions.OpenCount);
        Assert.Equal(1, catalog.EnrichCount);
        Assert.Equal(1, plan.CallCount);
        Assert.Equal(1, oracle.CallCount);
        Assert.Equal(1, guard.CaptureCount);
        Assert.Equal(2, guard.EnsureCount);
        Assert.Equal(1, sessions.LastSession.DisposeCount);
    }

    [Fact]
    public async Task Verify_query_denied_table_still_short_circuits_before_catalog()
    {
        RecordingSessionFactory sessions = new();
        RecordingCatalog catalog = new();

        VerificationPipeline pipeline = new(
            new UnresolvedParser("secret_table"),
            new YamlPolicyEngine(),
            new DenyUnresolvedAndTablePolicyLoader("secret_table"),
            new FixedContractLoader(),
            new FixedPathResolver(),
            new FixedAliasResolver(),
            sessions,
            catalog,
            new RecordingPlanProvider(),
            new RecordingOracle(),
            new RecordingGuard(),
            new PipelineRecordingRedactor());

        VerificationPipelineResult result = await pipeline.ExecuteAsync(
            new VerifyQueryRequest(
                "SELECT id FROM secret_table",
                "demo",
                "p.yaml",
                "c.yaml"),
            CancellationToken.None);

        Assert.Equal(AttestationDecision.Deny, result.Decision);
        Assert.Contains("denied_table", result.RedactedReasons);
        Assert.Equal(0, sessions.OpenCount);
        Assert.Equal(0, catalog.EnrichCount);
    }

    [Fact]
    public async Task Verify_query_unresolved_after_catalog_is_denied_before_plan()
    {
        RecordingSessionFactory sessions = new();
        PreservingCatalog catalog = new();
        RecordingPlanProvider plan = new();
        RecordingOracle oracle = new();
        RecordingGuard guard = new();

        VerificationPipeline pipeline = new(
            new UnresolvedParser("missing_relation"),
            new YamlPolicyEngine(),
            new DenyUnresolvedPolicyLoader(),
            new FixedContractLoader(),
            new FixedPathResolver(),
            new FixedAliasResolver(),
            sessions,
            catalog,
            plan,
            oracle,
            guard,
            new PipelineRecordingRedactor());

        VerificationPipelineResult result = await pipeline.ExecuteAsync(
            new VerifyQueryRequest(
                "SELECT id FROM missing_relation",
                "demo",
                "p.yaml",
                "c.yaml"),
            CancellationToken.None);

        Assert.Equal(AttestationDecision.Deny, result.Decision);
        Assert.Equal(1, sessions.OpenCount);
        Assert.Equal(1, catalog.EnrichCount);
        Assert.Equal(0, plan.CallCount);
        Assert.Equal(0, oracle.CallCount);
        Assert.Equal(0, guard.CaptureCount);
        Assert.Contains("unresolved_object", result.RedactedReasons);
        Assert.Equal(1, sessions.LastSession.DisposeCount);
    }

    [Fact]
    public async Task Verify_equivalence_resolvable_objects_reach_catalog_and_are_allowed()
    {
        RecordingSessionFactory sessions = new();
        RecordingCatalog catalog = new();
        RecordingPlanProvider plan = new();
        RecordingOracle oracle = new(static _ =>
        [
            new PropertyResult("query_equivalent", PropertyStatus.Pass, null),
        ]);
        RecordingGuard guard = new();

        VerifyEquivalenceUseCase useCase = CreateEquivalenceUseCase(
            new UnresolvedParser("resolved_users"),
            sessions,
            catalog,
            plan,
            oracle,
            guard);

        VerifyEquivalenceResponse response = await useCase.ExecuteAsync(
            new VerifyEquivalenceRequest(
                "SELECT id FROM resolved_users",
                "SELECT id FROM resolved_users",
                "demo",
                "p.yaml",
                "c.yaml"),
            CancellationToken.None);

        Assert.Equal(AttestationDecision.Pass, response.Attestation.Decision);
        Assert.Equal(1, sessions.OpenCount);
        Assert.Equal(2, catalog.EnrichCount);
        Assert.Equal(2, plan.CallCount);
        Assert.Equal(1, oracle.CallCount);
        Assert.Equal(1, guard.CaptureCount);
        Assert.Equal(2, guard.EnsureCount);
        Assert.Equal(1, sessions.LastSession.DisposeCount);
    }

    [Fact]
    public async Task Verify_equivalence_unresolved_after_catalog_is_denied_before_plan()
    {
        RecordingSessionFactory sessions = new();
        PreservingCatalog catalog = new();
        RecordingPlanProvider plan = new();
        RecordingOracle oracle = new(static _ =>
        [
            new PropertyResult("query_equivalent", PropertyStatus.Pass, null),
        ]);
        RecordingGuard guard = new();

        VerifyEquivalenceUseCase useCase = CreateEquivalenceUseCase(
            new UnresolvedParser("missing_relation"),
            sessions,
            catalog,
            plan,
            oracle,
            guard);

        VerifyEquivalenceResponse response = await useCase.ExecuteAsync(
            new VerifyEquivalenceRequest(
                "SELECT id FROM missing_relation",
                "SELECT id FROM missing_relation",
                "demo",
                "p.yaml",
                "c.yaml"),
            CancellationToken.None);

        Assert.Equal(AttestationDecision.Deny, response.Attestation.Decision);
        Assert.Equal(1, sessions.OpenCount);
        Assert.Equal(2, catalog.EnrichCount);
        Assert.Equal(0, plan.CallCount);
        Assert.Equal(0, oracle.CallCount);
        Assert.Equal(0, guard.CaptureCount);
        Assert.Equal(1, sessions.LastSession.DisposeCount);
    }

    private static VerifyEquivalenceUseCase CreateEquivalenceUseCase(
        ISqlParser parser,
        RecordingSessionFactory sessions,
        ICatalogResolver catalog,
        RecordingPlanProvider plan,
        RecordingOracle oracle,
        RecordingGuard guard)
    {
        PipelineRecordingRedactor redactor = new();
        return new VerifyEquivalenceUseCase(
            parser,
            new YamlPolicyEngine(),
            new DenyUnresolvedPolicyLoader(),
            new ConfigurableContractLoader(
                new Contract(
                    "c",
                    "1",
                    [new QueryEquivalentSpec()],
                    DisclosureProfileMerge.StrictDefaults())),
            new FixedPathResolver(),
            new FixedAliasResolver(),
            sessions,
            catalog,
            plan,
            oracle,
            guard,
            new AttestationFactory(new AttestationHmac(), redactor),
            new InMemoryStore(),
            redactor,
            HmacKey);
    }

    private sealed class UnresolvedParser(string objectName) : ISqlParser
    {
        private readonly string _objectName = objectName;

        public SqlParseResult Parse(string sql, CancellationToken cancellationToken)
        {
            SqlIr ir = new(
                "postgresql",
                ["Select"],
                [_objectName],
                [],
                ["id"],
                [],
                [],
                false,
                false,
                [_objectName],
                [],
                sql,
                "fp");

            return new SqlParseResult(true, ir, null, null);
        }
    }

    private sealed class DenyUnresolvedPolicyLoader : IPolicyLoader
    {
        public Task<Policy> LoadAsync(string path, CancellationToken cancellationToken) =>
            Task.FromResult(new Policy(
                "p",
                "1",
                ["Select"],
                [],
                [],
                [],
                denyUnresolvedObjects: true,
                denyMultipleStatements: true,
                denyUpdateDeleteWithoutPredicate: true,
                maxCostBucket: "high",
                forbiddenPlanNodes: [],
                disclosure: DisclosureProfileMerge.StrictDefaults()));
    }

    private sealed class DenyUnresolvedAndTablePolicyLoader(string deniedTable) : IPolicyLoader
    {
        private readonly string _deniedTable = deniedTable;

        public Task<Policy> LoadAsync(string path, CancellationToken cancellationToken) =>
            Task.FromResult(new Policy(
                "p",
                "1",
                ["Select"],
                [_deniedTable],
                [],
                [],
                denyUnresolvedObjects: true,
                denyMultipleStatements: true,
                denyUpdateDeleteWithoutPredicate: true,
                maxCostBucket: "high",
                forbiddenPlanNodes: [],
                disclosure: DisclosureProfileMerge.StrictDefaults()));
    }

    private sealed class PreservingCatalog : ICatalogResolver
    {
        public int EnrichCount { get; private set; }

        public Task<SqlAnalysis> EnrichAsync(
            SqlAnalysis analysis,
            TargetAlias target,
            IReadOnlySession session,
            CancellationToken cancellationToken)
        {
            EnrichCount++;
            return Task.FromResult(analysis);
        }
    }

    private sealed class InMemoryStore : IAttestationStore
    {
        private readonly Dictionary<string, Attestation> _attestations = new(StringComparer.Ordinal);

        public Task<string> SaveAsync(Attestation attestation, CancellationToken cancellationToken)
        {
            _attestations[attestation.Id] = attestation;
            return Task.FromResult(attestation.Id);
        }

        public Task<Attestation?> GetAsync(string attestationId, CancellationToken cancellationToken) =>
            Task.FromResult(
                _attestations.TryGetValue(attestationId, out Attestation? attestation)
                    ? attestation
                    : null);
    }
}
