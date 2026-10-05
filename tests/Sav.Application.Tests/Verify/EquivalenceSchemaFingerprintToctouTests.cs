using Sav.Application.Abstractions;
using Sav.Application.Attestations;
using Sav.Application.Verify;
using Sav.Domain.Analysis;
using Sav.Domain.Attestations;
using Sav.Domain.Decisions;
using Sav.Domain.Errors;
using Sav.Domain.Plans;
using Sav.Domain.Policies;
using Sav.Domain.Properties;
using Sav.Domain.Targets;
using Sav.Infrastructure.Storage.Attestations;

namespace Sav.Application.Tests.Verify;

public sealed class EquivalenceSchemaFingerprintToctouTests
{
    private static readonly byte[] Key = Enumerable.Repeat((byte)0x72, 32).ToArray();

    private const string LeftOnlyTable = "left_only";
    private const string RightOnlyTable = "right_only";

    [Fact]
    public async Task Schema_drift_on_right_only_relation_maps_to_review_attestation()
    {
        FakeStore store = new();
        RecordingOracle oracle = new(_ =>
        [
            new PropertyResult("query_equivalent", PropertyStatus.Pass, null),
        ]);
        VerifyEquivalenceUseCase useCase = CreateUseCase(
            new DriftOnRightOnlyRelationGuard(),
            store,
            oracle);

        VerifyEquivalenceResponse response = await useCase.ExecuteAsync(
            new VerifyEquivalenceRequest(
                $"SELECT 1 FROM {LeftOnlyTable}",
                $"SELECT 1 FROM {RightOnlyTable}",
                "demo",
                "p.yaml",
                "c.yaml"),
            CancellationToken.None);

        Assert.Equal(AttestationDecision.Review, response.Attestation.Decision);
        Assert.Equal(0, oracle.CallCount);
        Assert.Contains(
            SavErrorCode.SchemaChanged,
            response.Attestation.Analysis.Ir.RiskCodes,
            StringComparer.Ordinal);
        Assert.Contains(
            response.Attestation.Properties,
            p => p.Name == "schema_fingerprint"
                 && p.Status == PropertyStatus.Fail
                 && p.RedactedDetail == SavErrorCode.SchemaChanged);
    }

    [Fact]
    public async Task Equivalence_fingerprint_union_preserves_case_distinct_relations()
    {
        FakeStore store = new();
        RecordingCaseDistinctGuard guard = new();
        VerifyEquivalenceUseCase useCase = CreateUseCase(
            guard,
            store,
            parser: new CaseDistinctRelationParser());

        await useCase.ExecuteAsync(
            new VerifyEquivalenceRequest(
                "SELECT 1 FROM \"Orders\"",
                "SELECT 1 FROM orders",
                "demo",
                "p.yaml",
                "c.yaml"),
            CancellationToken.None);

        Assert.Equal(2, guard.CapturedTables.Count);
        Assert.Contains("Orders", guard.CapturedTables, StringComparer.Ordinal);
        Assert.Contains("orders", guard.CapturedTables, StringComparer.Ordinal);
    }

    [Fact]
    public async Task Schema_drift_on_s3_maps_to_review_before_oracle_result()
    {
        FakeStore store = new();
        RecordingOracle oracle = new(_ =>
        [
            new PropertyResult("query_equivalent", PropertyStatus.Pass, null),
        ]);
        VerifyEquivalenceUseCase useCase = CreateUseCase(
            new SchemaChangedOnEnsureGuard(throwOnEnsureCall: 2),
            store,
            oracle);

        VerifyEquivalenceResponse response = await useCase.ExecuteAsync(
            new VerifyEquivalenceRequest(
                $"SELECT 1 FROM {LeftOnlyTable}",
                $"SELECT 1 FROM {LeftOnlyTable}",
                "demo",
                "p.yaml",
                "c.yaml"),
            CancellationToken.None);

        Assert.Equal(AttestationDecision.Review, response.Attestation.Decision);
        Assert.Equal(0, oracle.CallCount);
        Assert.Contains(
            SavErrorCode.SchemaChanged,
            response.Attestation.Analysis.Ir.RiskCodes,
            StringComparer.Ordinal);
        Assert.Contains(
            response.Attestation.Properties,
            p => p.Name == "schema_fingerprint"
                 && p.Status == PropertyStatus.Fail
                 && p.RedactedDetail == SavErrorCode.SchemaChanged);
    }

    [Fact]
    public async Task Schema_guard_time_budget_starts_before_configuration_load()
    {
        FakeStore store = new();
        TimestampRecordingGuard guard = new();
        DelayedPolicyLoader policyLoader = new();
        VerifyEquivalenceUseCase useCase = CreateUseCase(
            guard,
            store,
            policyLoader: policyLoader);

        await useCase.ExecuteAsync(
            new VerifyEquivalenceRequest(
                $"SELECT 1 FROM {LeftOnlyTable}",
                $"SELECT 1 FROM {RightOnlyTable}",
                "demo",
                "p.yaml",
                "c.yaml"),
            CancellationToken.None);

        Assert.NotNull(policyLoader.LoadStartedUtc);
        Assert.NotNull(guard.FirstPipelineStartedUtc);
        Assert.True(guard.FirstPipelineStartedUtc <= policyLoader.LoadStartedUtc);
    }

    private static VerifyEquivalenceUseCase CreateUseCase(
        ISchemaFingerprintGuard guard,
        FakeStore store,
        RecordingOracle? oracle = null,
        ISqlParser? parser = null,
        IPolicyLoader? policyLoader = null)
    {
        PolicyDecision allow = new(PolicyOutcome.Allow, [], []);
        return new VerifyEquivalenceUseCase(
            parser ?? new TablePerSqlParser(),
            new ScriptedPolicyEngine(allow, allow, allow, allow),
            policyLoader ?? new FixedPolicyLoader(),
            new FixedEquivalenceContractLoader(),
            new FixedPathResolver(),
            new FixedAliasResolver(),
            new RecordingSessionFactory(),
            new RecordingCatalog(),
            new RecordingPlanProvider(PlanGateOutcome.Allow),
            oracle ?? new RecordingOracle(_ =>
            [
                new PropertyResult("query_equivalent", PropertyStatus.Pass, null),
            ]),
            guard,
            new AttestationFactory(new AttestationHmac(), new PipelineRecordingRedactor()),
            store,
            new PipelineRecordingRedactor(),
            Key);
    }

    /// <summary>
    /// Simulates schema drift on the right-only relation: throws
    /// <see cref="SavErrorCode.SchemaChanged"/> on Ensure when the fingerprinted
    /// analysis includes <see cref="RightOnlyTable"/>. Without a united IR the
    /// guard never sees that table and the oracle would run.
    /// </summary>
    private sealed class DriftOnRightOnlyRelationGuard : ISchemaFingerprintGuard
    {
        public Task<TargetSchemaFingerprint> CaptureBaselineAsync(
            IReadOnlySession session,
            TargetAlias target,
            SqlAnalysis analysis,
            CancellationToken cancellationToken) =>
            Task.FromResult(new TargetSchemaFingerprint("baseline"));

        public Task EnsureUnchangedAsync(
            IReadOnlySession session,
            TargetAlias target,
            SqlAnalysis analysis,
            TargetSchemaFingerprint baseline,
            DateTimeOffset pipelineStartedUtc,
            CancellationToken cancellationToken)
        {
            bool includesRightOnly = analysis.Ir.TablesRead
                .Concat(analysis.Ir.TablesWritten)
                .Any(t => string.Equals(t, RightOnlyTable, StringComparison.OrdinalIgnoreCase));
            if (includesRightOnly)
            {
                throw new SavException(SavErrorCode.SchemaChanged, "schema_changed: right_only drifted");
            }

            return Task.CompletedTask;
        }
    }

    private sealed class RecordingCaseDistinctGuard : ISchemaFingerprintGuard
    {
        public IReadOnlyList<string> CapturedTables { get; private set; } = [];

        public Task<TargetSchemaFingerprint> CaptureBaselineAsync(
            IReadOnlySession session,
            TargetAlias target,
            SqlAnalysis analysis,
            CancellationToken cancellationToken)
        {
            CapturedTables = analysis.Ir.TablesRead.ToArray();
            return Task.FromResult(new TargetSchemaFingerprint("baseline"));
        }

        public Task EnsureUnchangedAsync(
            IReadOnlySession session,
            TargetAlias target,
            SqlAnalysis analysis,
            TargetSchemaFingerprint baseline,
            DateTimeOffset pipelineStartedUtc,
            CancellationToken cancellationToken) =>
            Task.CompletedTask;
    }

    private sealed class CaseDistinctRelationParser : ISqlParser
    {
        public SqlParseResult Parse(string sql, CancellationToken cancellationToken)
        {
            string table = sql.Contains("\"Orders\"", StringComparison.Ordinal)
                ? "Orders"
                : "orders";
            SqlIr ir = new(
                "postgresql",
                ["Select"],
                [table],
                [],
                ["id"],
                [],
                [],
                false,
                false,
                [],
                [],
                sql,
                "fp-" + table);
            return new SqlParseResult(true, ir, null, null);
        }
    }

    private sealed class SchemaChangedOnEnsureGuard : ISchemaFingerprintGuard
    {
        private readonly int _throwOnEnsureCall;
        private int _ensureCount;

        public SchemaChangedOnEnsureGuard(int throwOnEnsureCall)
        {
            _throwOnEnsureCall = throwOnEnsureCall;
        }

        public Task<TargetSchemaFingerprint> CaptureBaselineAsync(
            IReadOnlySession session,
            TargetAlias target,
            SqlAnalysis analysis,
            CancellationToken cancellationToken) =>
            Task.FromResult(new TargetSchemaFingerprint("baseline"));

        public Task EnsureUnchangedAsync(
            IReadOnlySession session,
            TargetAlias target,
            SqlAnalysis analysis,
            TargetSchemaFingerprint baseline,
            DateTimeOffset pipelineStartedUtc,
            CancellationToken cancellationToken)
        {
            _ensureCount++;
            if (_ensureCount == _throwOnEnsureCall)
            {
                throw new SavException(SavErrorCode.SchemaChanged, "schema_changed: drift");
            }

            return Task.CompletedTask;
        }
    }

    private sealed class TimestampRecordingGuard : ISchemaFingerprintGuard
    {
        public DateTimeOffset? FirstPipelineStartedUtc { get; private set; }

        public Task<TargetSchemaFingerprint> CaptureBaselineAsync(
            IReadOnlySession session,
            TargetAlias target,
            SqlAnalysis analysis,
            CancellationToken cancellationToken) =>
            Task.FromResult(new TargetSchemaFingerprint("baseline"));

        public Task EnsureUnchangedAsync(
            IReadOnlySession session,
            TargetAlias target,
            SqlAnalysis analysis,
            TargetSchemaFingerprint baseline,
            DateTimeOffset pipelineStartedUtc,
            CancellationToken cancellationToken)
        {
            FirstPipelineStartedUtc ??= pipelineStartedUtc;
            return Task.CompletedTask;
        }
    }

    private sealed class DelayedPolicyLoader : IPolicyLoader
    {
        private readonly FixedPolicyLoader _inner = new();

        public DateTimeOffset? LoadStartedUtc { get; private set; }

        public async Task<Policy> LoadAsync(string path, CancellationToken cancellationToken)
        {
            LoadStartedUtc = DateTimeOffset.UtcNow;
            await Task.Delay(TimeSpan.FromMilliseconds(50), cancellationToken);
            return await _inner.LoadAsync(path, cancellationToken);
        }
    }

    private sealed class TablePerSqlParser : ISqlParser
    {
        public SqlParseResult Parse(string sql, CancellationToken cancellationToken)
        {
            string table = sql.Contains(RightOnlyTable, StringComparison.OrdinalIgnoreCase)
                ? RightOnlyTable
                : LeftOnlyTable;

            SqlIr ir = new(
                "postgresql",
                ["Select"],
                [table],
                [],
                ["id"],
                [],
                [],
                false,
                false,
                [],
                [],
                sql,
                "fp-" + table);
            return new SqlParseResult(true, ir, null, null);
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
}
