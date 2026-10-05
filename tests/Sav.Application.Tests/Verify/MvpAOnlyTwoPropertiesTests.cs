using Sav.Application.Verify;
using Sav.Domain.Contracts;
using Sav.Domain.Decisions;
using Sav.Domain.Plans;
using Sav.Domain.Policies;
using Sav.Domain.Properties;

namespace Sav.Application.Tests.Verify;

public sealed class MvpAOnlyTwoPropertiesTests
{
    [Fact]
    public async Task Oracle_receives_mvp_a_and_unique_non_null_on_real_alias()
    {
        RecordingOracle oracle = new(static request =>
            request.Specs
                .Select(s => new PropertyResult(s.Name, PropertyStatus.Pass, null))
                .ToArray());
        Contract contract = new(
            "c",
            "1",
            [
                new QuerySucceedsSpec(),
                new EmptyResultSpec(),
                new UniqueSpec("id"),
                new NonNullSpec("email"),
            ],
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
            new RecordingSessionFactory(),
            new RecordingCatalog(),
            new RecordingPlanProvider(PlanGateOutcome.Allow),
            oracle,
            new RecordingGuard(),
            new PipelineRecordingRedactor());

        VerificationPipelineResult result = await pipeline.ExecuteAsync(
            new VerifyQueryRequest("SELECT 1", "demo", "p.yaml", "c.yaml"),
            CancellationToken.None);

        Assert.Equal(AttestationDecision.Pass, result.Decision);
        Assert.NotNull(oracle.LastRequest);
        Assert.Equal(4, oracle.LastRequest!.Specs.Count);
        Assert.Collection(
            oracle.LastRequest.Specs,
            s => Assert.IsType<QuerySucceedsSpec>(s),
            s => Assert.IsType<EmptyResultSpec>(s),
            s => Assert.IsType<UniqueSpec>(s),
            s => Assert.IsType<NonNullSpec>(s));
        Assert.Equal(4, result.Properties.Count);
        Assert.Contains(result.Properties, p => p.Name == "query_succeeds");
        Assert.Contains(result.Properties, p => p.Name == "empty_result");
        Assert.Contains(result.Properties, p => p.Name == "unique");
        Assert.Contains(result.Properties, p => p.Name == "non_null");
    }
}
