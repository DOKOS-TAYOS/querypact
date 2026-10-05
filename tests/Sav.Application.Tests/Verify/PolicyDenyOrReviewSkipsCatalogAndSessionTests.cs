using Sav.Application.Verify;
using Sav.Domain.Decisions;

namespace Sav.Application.Tests.Verify;

public sealed class PolicyDenyOrReviewSkipsCatalogAndSessionTests
{
    [Theory]
    [InlineData(PolicyOutcome.Deny)]
    [InlineData(PolicyOutcome.Review)]
    public async Task First_policy_deny_or_review_skips_factory_catalog_plan_oracle_guard(
        PolicyOutcome outcome)
    {
        RecordingSessionFactory sessions = new();
        RecordingCatalog catalog = new();
        RecordingPlanProvider plan = new();
        RecordingOracle oracle = new();
        RecordingGuard guard = new();

        VerificationPipeline pipeline = new(
            new FixedParser(success: true),
            new ScriptedPolicyEngine(new PolicyDecision(outcome, [outcome.ToString()], [outcome.ToString()])),
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

        Assert.Equal(
            outcome == PolicyOutcome.Review ? AttestationDecision.Review : AttestationDecision.Deny,
            result.Decision);
        Assert.Equal(0, sessions.OpenCount);
        Assert.Equal(0, catalog.EnrichCount);
        Assert.Equal(0, plan.CallCount);
        Assert.Equal(0, oracle.CallCount);
        Assert.Equal(0, guard.CaptureCount);
        Assert.Equal(0, guard.EnsureCount);
    }

    [Fact]
    public async Task Unparsable_skips_factory_catalog_plan_oracle_guard()
    {
        RecordingSessionFactory sessions = new();
        RecordingCatalog catalog = new();
        RecordingPlanProvider plan = new();
        RecordingOracle oracle = new();
        RecordingGuard guard = new();

        VerificationPipeline pipeline = new(
            new FixedParser(success: false),
            new ScriptedPolicyEngine(new PolicyDecision(PolicyOutcome.Deny, ["sql_unparsable"], ["sql_unparsable"])),
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

        _ = await pipeline.ExecuteAsync(
            new VerifyQueryRequest("SELEC", "demo", "p.yaml", "c.yaml"),
            CancellationToken.None);

        Assert.Equal(0, sessions.OpenCount);
        Assert.Equal(0, catalog.EnrichCount);
        Assert.Equal(0, plan.CallCount);
        Assert.Equal(0, oracle.CallCount);
        Assert.Equal(0, guard.CaptureCount);
    }
}
