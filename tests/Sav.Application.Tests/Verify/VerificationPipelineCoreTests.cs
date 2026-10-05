using Sav.Application.Verify;
using Sav.Domain.Decisions;

namespace Sav.Application.Tests.Verify;

public sealed class VerificationPipelineCoreTests
{
    [Fact]
    public async Task Unparsable_returns_deny_without_session()
    {
        RecordingSessionFactory sessions = new();
        RecordingCatalog catalog = new();
        RecordingPlanProvider plan = new();
        RecordingOracle oracle = new();
        RecordingGuard guard = new();
        VerificationPipeline pipeline = Create(
            new FixedParser(success: false),
            new ScriptedPolicyEngine(new PolicyDecision(PolicyOutcome.Deny, ["sql_unparsable"], ["sql_unparsable"])),
            sessions,
            catalog,
            plan,
            oracle,
            guard);

        VerificationPipelineResult result = await pipeline.ExecuteAsync(SampleRequest(), CancellationToken.None);

        Assert.Equal(AttestationDecision.Deny, result.Decision);
        Assert.False(result.Analysis.IsParsable);
        Assert.Equal(0, sessions.OpenCount);
        Assert.Equal(0, catalog.EnrichCount);
        Assert.Equal(0, plan.CallCount);
        Assert.Equal(0, oracle.CallCount);
        Assert.Equal(0, guard.CaptureCount);
    }

    [Fact]
    public async Task First_review_returns_review_without_session()
    {
        RecordingSessionFactory sessions = new();
        VerificationPipeline pipeline = Create(
            new FixedParser(success: true),
            new ScriptedPolicyEngine(new PolicyDecision(PolicyOutcome.Review, ["needs_review"], ["needs_review"])),
            sessions,
            new RecordingCatalog(),
            new RecordingPlanProvider(),
            new RecordingOracle(),
            new RecordingGuard());

        VerificationPipelineResult result = await pipeline.ExecuteAsync(SampleRequest(), CancellationToken.None);

        Assert.Equal(AttestationDecision.Review, result.Decision);
        Assert.Equal(0, sessions.OpenCount);
    }

    private static VerificationPipeline Create(
        FixedParser parser,
        ScriptedPolicyEngine engine,
        RecordingSessionFactory sessions,
        RecordingCatalog catalog,
        RecordingPlanProvider plan,
        RecordingOracle oracle,
        RecordingGuard guard) =>
        new(
            parser,
            engine,
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

    private static VerifyQueryRequest SampleRequest() =>
        new("SELECT 1", "demo", "policy.yaml", "contract.yaml");
}
