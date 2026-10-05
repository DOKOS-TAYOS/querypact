using Sav.Application.Verify;
using Sav.Domain.Decisions;
using Sav.Domain.Plans;

namespace Sav.Application.Tests.Verify;

public sealed class NoExplainOnDenyOrReviewPipelineTests
{
    [Fact]
    public async Task First_policy_deny_never_invokes_plan_provider()
    {
        RecordingPlanProvider plan = new();
        VerificationPipeline pipeline = new(
            new FixedParser(success: true),
            new ScriptedPolicyEngine(new PolicyDecision(PolicyOutcome.Deny, ["denied"], ["denied"])),
            new FixedPolicyLoader(),
            new FixedContractLoader(),
            new FixedPathResolver(),
            new FixedAliasResolver(),
            new RecordingSessionFactory(),
            new RecordingCatalog(),
            plan,
            new RecordingOracle(),
            new RecordingGuard(),
            new PipelineRecordingRedactor());

        _ = await pipeline.ExecuteAsync(
            new VerifyQueryRequest("SELECT 1", "demo", "p.yaml", "c.yaml"),
            CancellationToken.None);

        Assert.Equal(0, plan.CallCount);
    }

    [Fact]
    public async Task Second_policy_review_never_invokes_plan_provider()
    {
        RecordingPlanProvider plan = new();
        VerificationPipeline pipeline = new(
            new FixedParser(success: true),
            new ScriptedPolicyEngine(
                new PolicyDecision(PolicyOutcome.Allow, [], []),
                new PolicyDecision(PolicyOutcome.Review, ["needs_review"], ["needs_review"])),
            new FixedPolicyLoader(),
            new FixedContractLoader(),
            new FixedPathResolver(),
            new FixedAliasResolver(),
            new RecordingSessionFactory(),
            new RecordingCatalog(),
            plan,
            new RecordingOracle(),
            new RecordingGuard(),
            new PipelineRecordingRedactor());

        VerificationPipelineResult result = await pipeline.ExecuteAsync(
            new VerifyQueryRequest("SELECT 1", "demo", "p.yaml", "c.yaml"),
            CancellationToken.None);

        Assert.Equal(AttestationDecision.Review, result.Decision);
        Assert.Equal(0, plan.CallCount);
    }

    [Fact]
    public async Task Plan_called_only_with_allow_decision_and_non_null_session()
    {
        RecordingPlanProvider plan = new(PlanGateOutcome.Allow);
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
            new RecordingOracle(),
            new RecordingGuard(),
            new PipelineRecordingRedactor());

        _ = await pipeline.ExecuteAsync(
            new VerifyQueryRequest("SELECT 1", "demo", "p.yaml", "c.yaml"),
            CancellationToken.None);

        Assert.Equal(1, plan.CallCount);
        Assert.Equal(PolicyOutcome.Allow, plan.LastDecision!.Outcome);
        Assert.NotNull(plan.LastSession);
    }
}
