using Sav.Application.Verify;
using Sav.Domain.Decisions;
using Sav.Domain.Plans;

namespace Sav.Application.Tests.Verify;

public sealed class PipelineSingleSessionOwnershipTests
{
    [Fact]
    public async Task Allow_to_catalog_opens_exactly_one_session_passed_to_catalog()
    {
        RecordingSessionFactory sessions = new();
        RecordingCatalog catalog = new();
        RecordingGuard guard = new();

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
            catalog,
            new RecordingPlanProvider(PlanGateOutcome.Allow),
            new RecordingOracle(),
            guard,
            new PipelineRecordingRedactor());

        _ = await pipeline.ExecuteAsync(
            new VerifyQueryRequest("SELECT 1", "demo", "p.yaml", "c.yaml"),
            CancellationToken.None);

        Assert.Equal(1, sessions.OpenCount);
        Assert.Same(sessions.LastSession, catalog.ReceivedSession);
        Assert.Equal(1, sessions.LastSession.DisposeCount);
        Assert.Equal(0, guard.FactoryOpenAttempts);
    }
}
