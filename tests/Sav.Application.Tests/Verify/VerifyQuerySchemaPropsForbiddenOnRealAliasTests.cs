using Sav.Application.Verify;
using Sav.Domain.Contracts;
using Sav.Domain.Decisions;
using Sav.Domain.Errors;
using Sav.Domain.Plans;
using Sav.Domain.Policies;
using Sav.Domain.Properties;

namespace Sav.Application.Tests.Verify;

/// <summary>
/// M008d: schema_invariant / no_new_orphans / affected_rows on verify_query real alias
/// must surface <see cref="SavErrorCode.PropertyEnvironmentForbidden"/> (ephemeral-only).
/// </summary>
public sealed class VerifyQuerySchemaPropsForbiddenOnRealAliasTests
{
    [Fact]
    public async Task Schema_invariant_and_orphans_on_real_alias_are_property_environment_forbidden()
    {
        RecordingOracle oracle = new();
        RecordingSessionFactory sessions = new();
        Contract contract = new(
            "schema-on-real",
            "1",
            [
                new QuerySucceedsSpec(),
                new SchemaInvariantSpec(
                [
                    new SchemaInvariantRequirement("public.t", "r"),
                ]),
                new NoNewOrphansSpec("public.parent", "id", "public.child", "parent_id"),
                new AffectedRowsSpec(0, 10),
            ],
            DisclosureProfileMerge.StrictDefaults());

        VerificationPipeline pipeline = CreatePipeline(contract, oracle, sessions);

        VerificationPipelineResult result = await pipeline.ExecuteAsync(
            new VerifyQueryRequest("SELECT 1", "demo", "p.yaml", "c.yaml"),
            CancellationToken.None);

        Assert.Equal(AttestationDecision.Fail, result.Decision);
        Assert.Contains(
            result.Properties,
            p => p.Name == "schema_invariant"
                 && p.Status == PropertyStatus.Error
                 && p.RedactedDetail == SavErrorCode.PropertyEnvironmentForbidden);
        Assert.Contains(
            result.Properties,
            p => p.Name == "no_new_orphans"
                 && p.Status == PropertyStatus.Error
                 && p.RedactedDetail == SavErrorCode.PropertyEnvironmentForbidden);
        Assert.Contains(
            result.Properties,
            p => p.Name == "affected_rows"
                 && p.Status == PropertyStatus.Error
                 && p.RedactedDetail == SavErrorCode.PropertyEnvironmentForbidden);

        Assert.NotNull(oracle.LastRequest);
        Assert.DoesNotContain(oracle.LastRequest!.Specs, static s => s is SchemaInvariantSpec);
        Assert.DoesNotContain(oracle.LastRequest.Specs, static s => s is NoNewOrphansSpec);
        Assert.DoesNotContain(oracle.LastRequest.Specs, static s => s is AffectedRowsSpec);
        Assert.Contains(oracle.LastRequest.Specs, static s => s is QuerySucceedsSpec);
    }

    [Fact]
    public async Task Unique_and_non_null_are_passed_to_oracle_on_real_alias()
    {
        RecordingOracle oracle = new(static request =>
            request.Specs
                .Select(s => new PropertyResult(s.Name, PropertyStatus.Pass, null))
                .ToArray());
        Contract contract = new(
            "mvp-b-read",
            "1",
            [
                new UniqueSpec("id"),
                new NonNullSpec("email"),
            ],
            DisclosureProfileMerge.StrictDefaults());

        VerificationPipeline pipeline = CreatePipeline(contract, oracle, new RecordingSessionFactory());

        VerificationPipelineResult result = await pipeline.ExecuteAsync(
            new VerifyQueryRequest("SELECT 1", "demo", "p.yaml", "c.yaml"),
            CancellationToken.None);

        Assert.Equal(AttestationDecision.Pass, result.Decision);
        Assert.NotNull(oracle.LastRequest);
        Assert.Equal(2, oracle.LastRequest!.Specs.Count);
        Assert.Collection(
            oracle.LastRequest.Specs,
            s => Assert.IsType<UniqueSpec>(s),
            s => Assert.IsType<NonNullSpec>(s));
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
}
