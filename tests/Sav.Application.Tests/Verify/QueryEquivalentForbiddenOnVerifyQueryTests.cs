using Sav.Application.Verify;
using Sav.Domain.Contracts;
using Sav.Domain.Decisions;
using Sav.Domain.Errors;
using Sav.Domain.Plans;
using Sav.Domain.Policies;
using Sav.Domain.Properties;

namespace Sav.Application.Tests.Verify;

/// <summary>
/// M010b-B H1: query_equivalent (and unknown specs) must not be silently dropped on verify_query.
/// </summary>
public sealed class QueryEquivalentForbiddenOnVerifyQueryTests
{
    [Fact]
    public async Task Query_succeeds_plus_query_equivalent_on_verify_query_must_not_pass_silently()
    {
        RecordingOracle oracle = new(static request =>
            request.Specs
                .Select(s => new PropertyResult(s.Name, PropertyStatus.Pass, null))
                .ToArray());
        RecordingSessionFactory sessions = new();
        Contract contract = new(
            "qs-plus-qe",
            "1",
            [new QuerySucceedsSpec(), new QueryEquivalentSpec()],
            DisclosureProfileMerge.StrictDefaults());

        VerificationPipeline pipeline = CreatePipeline(contract, oracle, sessions);

        VerificationPipelineResult result = await pipeline.ExecuteAsync(
            new VerifyQueryRequest("SELECT 1", "demo", "p.yaml", "c.yaml"),
            CancellationToken.None);

        Assert.NotEqual(AttestationDecision.Pass, result.Decision);
        Assert.Contains(
            result.Properties,
            p => p.Name == "query_equivalent"
                 && p.Status == PropertyStatus.Error
                 && p.RedactedDetail == SavErrorCode.UnsupportedConstruct);
        Assert.DoesNotContain(
            oracle.LastRequest?.Specs ?? [],
            static s => s is QueryEquivalentSpec);
    }

    [Fact]
    public async Task Unknown_property_spec_on_verify_query_must_not_pass_silently()
    {
        RecordingOracle oracle = new(static request =>
            request.Specs
                .Select(s => new PropertyResult(s.Name, PropertyStatus.Pass, null))
                .ToArray());
        Contract contract = new(
            "unknown-prop",
            "1",
            [new QuerySucceedsSpec(), new UnknownFuturePropertySpec()],
            DisclosureProfileMerge.StrictDefaults());

        VerificationPipeline pipeline = CreatePipeline(contract, oracle, new RecordingSessionFactory());

        VerificationPipelineResult result = await pipeline.ExecuteAsync(
            new VerifyQueryRequest("SELECT 1", "demo", "p.yaml", "c.yaml"),
            CancellationToken.None);

        Assert.NotEqual(AttestationDecision.Pass, result.Decision);
        Assert.Contains(
            result.Properties,
            p => p.Name == "unknown_future_prop"
                 && p.Status == PropertyStatus.Error
                 && p.RedactedDetail == SavErrorCode.UnsupportedConstruct);
    }

    private static VerificationPipeline CreatePipeline(
        Contract contract,
        RecordingOracle oracle,
        RecordingSessionFactory sessions) =>
        new(
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

    private sealed record UnknownFuturePropertySpec() : PropertySpec("unknown_future_prop");
}
