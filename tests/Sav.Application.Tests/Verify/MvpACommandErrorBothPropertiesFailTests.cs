using Sav.Application.Verify;
using Sav.Domain.Decisions;
using Sav.Domain.Plans;
using Sav.Domain.Properties;

namespace Sav.Application.Tests.Verify;

public sealed class MvpACommandErrorBothPropertiesFailTests
{
    [Fact]
    public async Task Command_error_maps_both_mvp_a_properties_to_fail_and_decision_fail()
    {
        RecordingOracle oracle = new(_ =>
        [
            new PropertyResult("query_succeeds", PropertyStatus.Fail, "query_failed"),
            new PropertyResult("empty_result", PropertyStatus.Error, "query_failed"),
        ]);

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
            new RecordingPlanProvider(PlanGateOutcome.Allow),
            oracle,
            new RecordingGuard(),
            new PipelineRecordingRedactor());

        VerificationPipelineResult result = await pipeline.ExecuteAsync(
            new VerifyQueryRequest("SELECT bad", "demo", "p.yaml", "c.yaml"),
            CancellationToken.None);

        Assert.Equal(AttestationDecision.Fail, result.Decision);
        Assert.Equal(2, result.Properties.Count);
        Assert.All(
            result.Properties,
            p =>
            {
                Assert.True(p.Status is PropertyStatus.Fail or PropertyStatus.Error);
                Assert.Equal("query_failed", p.RedactedDetail);
                Assert.NotEqual(PropertyStatus.NotEvaluated, p.Status);
            });
        Assert.Contains(result.Properties, p => p.Name == "query_succeeds");
        Assert.Contains(result.Properties, p => p.Name == "empty_result");
    }
}
