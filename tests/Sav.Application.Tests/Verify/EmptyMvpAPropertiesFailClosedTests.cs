using Sav.Application.Verify;
using Sav.Domain.Contracts;
using Sav.Domain.Decisions;
using Sav.Domain.Errors;
using Sav.Domain.Plans;
using Sav.Domain.Policies;

namespace Sav.Application.Tests.Verify;

public sealed class EmptyMvpAPropertiesFailClosedTests
{
    [Fact]
    public async Task Empty_required_properties_yield_review_before_session_and_plan()
    {
        RecordingOracle oracle = new();
        RecordingSessionFactory sessions = new();
        RecordingPlanProvider plan = new(PlanGateOutcome.Allow);
        Contract contract = new(
            "empty-props",
            "1",
            [],
            DisclosureProfileMerge.StrictDefaults());

        VerificationPipeline pipeline = new(
            new FixedParser(success: true),
            new ScriptedPolicyEngine(
                new PolicyDecision(PolicyOutcome.Allow, [], []),
                new PolicyDecision(PolicyOutcome.Allow, [], [])),
            new FixedPolicyLoader(),
            new ConfigurableContractLoader(contract),
            new FixedPathResolver(),
            new FixedAliasResolver(),
            sessions,
            new RecordingCatalog(),
            plan,
            oracle,
            new RecordingGuard(),
            new PipelineRecordingRedactor());

        VerificationPipelineResult result = await pipeline.ExecuteAsync(
            new VerifyQueryRequest("SELECT 1", "demo", "p.yaml", "c.yaml"),
            CancellationToken.None);

        Assert.Equal(AttestationDecision.Review, result.Decision);
        Assert.Equal(0, sessions.OpenCount);
        Assert.Equal(0, plan.CallCount);
        Assert.Equal(0, oracle.CallCount);
        Assert.Contains(
            result.Properties,
            p => p.Name == "mvp_a_properties"
                 && p.Status == PropertyStatus.NotEvaluated
                 && p.RedactedDetail == SavErrorCode.MvpAPropertiesRequired);
        Assert.Contains(SavErrorCode.MvpAPropertiesRequired, result.RedactedReasons);
    }

    [Fact]
    public async Task Query_equivalent_only_on_verify_query_still_fail_closed()
    {
        // query_equivalent is owned by VerifyEquivalenceUseCase, not verify_query.
        // After M010b-B H1 it surfaces as unsupported_construct (never silent drop → PASS).
        RecordingOracle oracle = new();
        RecordingSessionFactory sessions = new();
        Contract contract = new(
            "equiv-only",
            "1",
            [new QueryEquivalentSpec()],
            DisclosureProfileMerge.StrictDefaults());

        VerificationPipeline pipeline = new(
            new FixedParser(success: true),
            new ScriptedPolicyEngine(
                new PolicyDecision(PolicyOutcome.Allow, [], []),
                new PolicyDecision(PolicyOutcome.Allow, [], [])),
            new FixedPolicyLoader(),
            new ConfigurableContractLoader(contract),
            new FixedPathResolver(),
            new FixedAliasResolver(),
            sessions,
            new RecordingCatalog(),
            new RecordingPlanProvider(PlanGateOutcome.Allow),
            oracle,
            new RecordingGuard(),
            new PipelineRecordingRedactor());

        VerificationPipelineResult result = await pipeline.ExecuteAsync(
            new VerifyQueryRequest("SELECT 1", "demo", "p.yaml", "c.yaml"),
            CancellationToken.None);

        Assert.Equal(AttestationDecision.Fail, result.Decision);
        Assert.Equal(0, sessions.OpenCount);
        Assert.Equal(0, oracle.CallCount);
        Assert.Contains(
            result.Properties,
            p => p.Name == "query_equivalent"
                 && p.Status == PropertyStatus.Error
                 && p.RedactedDetail == SavErrorCode.UnsupportedConstruct);
    }
}
