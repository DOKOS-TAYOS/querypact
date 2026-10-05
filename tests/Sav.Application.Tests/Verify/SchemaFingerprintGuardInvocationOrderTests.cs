using Sav.Application.Verify;
using Sav.Domain.Decisions;
using Sav.Domain.Plans;

namespace Sav.Application.Tests.Verify;

public sealed class SchemaFingerprintGuardInvocationOrderTests
{
    [Fact]
    public async Task Allow_path_invokes_S1_S2_S3_with_pipeline_session()
    {
        RecordingSessionFactory sessions = new();
        RecordingGuard guard = new();
        RecordingOracle oracle = new();

        VerificationPipeline pipeline = new(
            new FixedParser(success: true),
            new ScriptedPolicyEngine(
                new PolicyDecision(PolicyOutcome.Allow, [], []),
                new PolicyDecision(PolicyOutcome.Allow, [], [])),
            new FixedPolicyLoader(),
            new FixedContractLoader(),
            new FixedPathResolver(),
            new FixedAliasResolver(),
            sessions,
            new RecordingCatalog(),
            new RecordingPlanProvider(PlanGateOutcome.Allow),
            oracle,
            guard,
            new PipelineRecordingRedactor());

        VerificationPipelineResult result = await pipeline.ExecuteAsync(
            new VerifyQueryRequest("SELECT 1", "demo", "p.yaml", "c.yaml"),
            CancellationToken.None);

        Assert.Equal(AttestationDecision.Pass, result.Decision);
        Assert.Equal(
            ["S1_CaptureBaseline", "S2_EnsureUnchanged", "S3_EnsureUnchanged"],
            guard.InvocationOrder);
        Assert.Equal(1, guard.CaptureCount);
        Assert.Equal(2, guard.EnsureCount);
        Assert.Equal(1, oracle.CallCount);
        Assert.Equal(3, guard.SessionsSeen.Count);
        Assert.All(guard.SessionsSeen, s => Assert.Same(sessions.LastSession, s));
        Assert.Same(sessions.LastSession, oracle.LastRequest?.Session);
        Assert.Equal(0, guard.FactoryOpenAttempts);
    }
}
