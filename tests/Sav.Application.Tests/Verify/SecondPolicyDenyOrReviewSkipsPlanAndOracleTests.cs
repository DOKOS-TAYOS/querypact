using Sav.Application.Verify;
using Sav.Domain.Decisions;

namespace Sav.Application.Tests.Verify;

public sealed class SecondPolicyDenyOrReviewSkipsPlanAndOracleTests
{
    [Theory]
    [InlineData(PolicyOutcome.Deny, AttestationDecision.Deny)]
    [InlineData(PolicyOutcome.Review, AttestationDecision.Review)]
    public async Task Second_policy_deny_or_review_skips_plan_oracle_and_guard(
        PolicyOutcome secondOutcome,
        AttestationDecision expected)
    {
        RecordingSessionFactory sessions = new();
        RecordingCatalog catalog = new();
        RecordingPlanProvider plan = new();
        RecordingOracle oracle = new();
        RecordingGuard guard = new();

        VerificationPipeline pipeline = new(
            new FixedParser(success: true),
            new ScriptedPolicyEngine(
                new PolicyDecision(PolicyOutcome.Allow, [], []),
                new PolicyDecision(secondOutcome, [secondOutcome.ToString()], [secondOutcome.ToString()])),
            new FixedPolicyLoader(),
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
            new VerifyQueryRequest("SELECT 1", "demo", "p.yaml", "c.yaml"),
            CancellationToken.None);

        Assert.Equal(expected, result.Decision);
        Assert.Equal(1, sessions.OpenCount);
        Assert.Equal(1, catalog.EnrichCount);
        Assert.Equal(1, sessions.LastSession.DisposeCount);
        Assert.Equal(0, plan.CallCount);
        Assert.Equal(0, oracle.CallCount);
        Assert.Equal(0, guard.CaptureCount);
        Assert.Equal(0, guard.EnsureCount);
        Assert.Null(result.PlanSummary);
    }
}
