using Sav.Application.Abstractions;
using Sav.Application.Attestations;
using Sav.Application.Verify;
using Sav.Domain.Analysis;
using Sav.Domain.Attestations;
using Sav.Domain.Decisions;
using Sav.Domain.Targets;
using Sav.Infrastructure.Config.Policies;
using Sav.Infrastructure.Storage.Attestations;

namespace Sav.Application.Tests.Verify;

public sealed class ConversionPolicyGateTests
{
    [Fact]
    public async Task Single_conversion_rejection_skips_plan_oracle_and_fingerprint()
    {
        RecordingSessionFactory sessions = new();
        ConversionCatalog catalog = new();
        RecordingPlanProvider plan = new();
        RecordingOracle oracle = new();
        RecordingGuard guard = new();
        VerificationPipeline pipeline = new(
            new ConversionParser(), new YamlPolicyEngine(), new FixedPolicyLoader(), new FixedContractLoader(),
            new FixedPathResolver(), new FixedAliasResolver(), sessions, catalog, plan, oracle, guard,
            new PipelineRecordingRedactor());

        VerificationPipelineResult result = await pipeline.ExecuteAsync(
            new VerifyQueryRequest("SELECT '7'::integer FROM items", "demo", "p.yaml", "c.yaml"),
            CancellationToken.None);

        Assert.Equal(AttestationDecision.Deny, result.Decision);
        Assert.Contains("unsupported_construct", result.RedactedReasons);
        Assert.Equal(1, catalog.SingleCalls);
        Assert.Equal(1, sessions.OpenCount);
        Assert.Equal(1, sessions.LastSession.DisposeCount);
        Assert.Equal(0, plan.CallCount);
        Assert.Equal(0, oracle.CallCount);
        Assert.Equal(0, guard.CaptureCount);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Pair_conversion_rejection_on_either_side_skips_both_plans_and_oracle(bool castOnLeft)
    {
        RecordingSessionFactory sessions = new();
        ConversionCatalog catalog = new();
        RecordingPlanProvider plan = new();
        RecordingOracle oracle = new();
        RecordingGuard guard = new();
        PipelineRecordingRedactor redactor = new();
        byte[] key = Enumerable.Repeat((byte)0x41, 32).ToArray();
        VerifyEquivalenceUseCase useCase = new(
            new ConversionParser(), new YamlPolicyEngine(), new FixedPolicyLoader(),
            new FixedEquivalenceContractLoader(), new FixedPathResolver(), new FixedAliasResolver(),
            sessions, catalog, plan, oracle, guard, new AttestationFactory(new AttestationHmac(), redactor),
            new MemoryStore(), redactor, key);
        const string cast = "SELECT '7'::integer FROM items";
        const string plain = "SELECT 7 FROM items";

        VerifyEquivalenceResponse response = await useCase.ExecuteAsync(
            new VerifyEquivalenceRequest(castOnLeft ? cast : plain, castOnLeft ? plain : cast,
                "demo", "p.yaml", "c.yaml"), CancellationToken.None);

        Assert.Equal(AttestationDecision.Deny, response.Attestation.Decision);
        Assert.Equal(1, catalog.PairCalls);
        Assert.Equal(0, catalog.SingleCalls);
        Assert.Equal(1, sessions.OpenCount);
        Assert.Equal(1, sessions.LastSession.DisposeCount);
        Assert.Equal(0, plan.CallCount);
        Assert.Equal(0, oracle.CallCount);
        Assert.Equal(0, guard.CaptureCount);
        Assert.True(AttestationFactory.VerifyIntegrity(response.Attestation, new AttestationHmac(), key));
    }

    private sealed class ConversionParser : ISqlParser
    {
        public SqlParseResult Parse(string sql, CancellationToken cancellationToken) => new(true,
            new SqlIr("postgresql", ["Select"], ["items"], [], [], [], [], false, false,
                ["items"], [], sql, "fp", [], [], sql.Contains("::", StringComparison.Ordinal) ? ["pg_catalog.int4"] : []),
            null, null);
    }

    private sealed class ConversionCatalog : ICatalogPairResolver
    {
        public int SingleCalls { get; private set; }
        public int PairCalls { get; private set; }

        public Task<SqlAnalysis> EnrichAsync(SqlAnalysis analysis, TargetAlias target,
            IReadOnlySession session, CancellationToken cancellationToken)
        {
            SingleCalls++;
            Assert.Equal(["pg_catalog.int4"], analysis.Ir.TypeReferences);
            return Task.FromResult(Reject(analysis));
        }

        public Task<(SqlAnalysis Left, SqlAnalysis Right)> EnrichPairAsync(SqlAnalysis left, SqlAnalysis right,
            TargetAlias target, IReadOnlySession session, CancellationToken cancellationToken)
        {
            PairCalls++;
            Assert.Single(left.Ir.TypeReferences.Concat(right.Ir.TypeReferences));
            return Task.FromResult((Reject(left), Reject(right)));
        }

        private static SqlAnalysis Reject(SqlAnalysis analysis)
        {
            SqlIr ir = analysis.Ir;
            return new SqlAnalysis(new SqlIr(ir.Dialect, ir.StatementTypes, ir.TablesRead, ir.TablesWritten,
                ir.ColumnsRead, ir.ColumnsWritten, ir.Functions, ir.HasMultipleStatements, ir.HasDynamicSql,
                [], ["unsupported_construct"], ir.NormalizedSql, ir.Fingerprint, ir.Operators,
                ir.FunctionReferences, ir.TypeReferences), true);
        }
    }

    private sealed class MemoryStore : IAttestationStore
    {
        public Task<string> SaveAsync(Attestation attestation, CancellationToken cancellationToken) =>
            Task.FromResult(attestation.Id);

        public Task<Attestation?> GetAsync(string attestationId, CancellationToken cancellationToken) =>
            Task.FromResult<Attestation?>(null);
    }
}
