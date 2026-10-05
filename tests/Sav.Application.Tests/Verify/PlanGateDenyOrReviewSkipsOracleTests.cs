using Sav.Application.Verify;
using Sav.Domain.Decisions;
using Sav.Domain.Plans;

namespace Sav.Application.Tests.Verify;

public sealed class PlanGateDenyOrReviewSkipsOracleTests
{
    [Theory]
    [InlineData(PlanGateOutcome.Deny, AttestationDecision.Deny)]
    [InlineData(PlanGateOutcome.Review, AttestationDecision.Review)]
    public async Task Plan_deny_or_review_skips_oracle(
        PlanGateOutcome planOutcome,
        AttestationDecision expected)
    {
        RecordingOracle oracle = new();
        RecordingPlanProvider plan = new(planOutcome);

        VerificationPipeline pipeline = new(
            new FixedParser(success: true),
            new ScriptedPolicyEngine(
                new PolicyDecision(PolicyOutcome.Allow, [], []),
                new PolicyDecision(PolicyOutcome.Allow, [], [])),
            new FixedPolicyLoader(),
            new FixedContractLoader(),
            new FixedPathResolver(),
            new FixedAliasResolver(),
            new RecordingSessionFactory(),
            new RecordingCatalog(),
            plan,
            oracle,
            new RecordingGuard(),
            new PipelineRecordingRedactor());

        VerificationPipelineResult result = await pipeline.ExecuteAsync(
            new VerifyQueryRequest("SELECT 1", "demo", "p.yaml", "c.yaml"),
            CancellationToken.None);

        Assert.Equal(expected, result.Decision);
        Assert.Equal(1, plan.CallCount);
        Assert.Equal(0, oracle.CallCount);
        Assert.NotNull(plan.LastSession);
    }
}
