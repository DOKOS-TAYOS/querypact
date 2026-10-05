using Sav.Application.Verify;
using Sav.Domain.Decisions;
using Sav.Domain.Plans;

namespace Sav.Application.Tests.Verify;

public sealed class VerifyPipelineUsesAliasResolverPortTests
{
    [Fact]
    public async Task Pipeline_resolves_target_alias_via_injected_port()
    {
        RecordingAliasResolver aliases = new();
        RecordingOracle oracle = new();

        VerificationPipeline pipeline = new(
            new FixedParser(success: true),
            new ScriptedPolicyEngine(
                new PolicyDecision(PolicyOutcome.Allow, [], []),
                new PolicyDecision(PolicyOutcome.Allow, [], [])),
            new FixedPolicyLoader(),
            new FixedContractLoader(),
            new FixedPathResolver(),
            aliases,
            new RecordingSessionFactory(),
            new RecordingCatalog(),
            new RecordingPlanProvider(PlanGateOutcome.Allow),
            oracle,
            new RecordingGuard(),
            new PipelineRecordingRedactor());

        VerificationPipelineResult result = await pipeline.ExecuteAsync(
            new VerifyQueryRequest("SELECT 1", "prod-ro", "p.yaml", "c.yaml"),
            CancellationToken.None);

        Assert.Equal(AttestationDecision.Pass, result.Decision);
        Assert.Equal(1, aliases.ResolveCount);
        Assert.Equal("prod-ro", aliases.LastAlias);
        Assert.Equal("prod-ro", oracle.LastRequest?.Target?.Alias);
    }
}
