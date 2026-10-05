using Sav.Application.Analyze;
using Sav.Domain.Contracts;
using Sav.Domain.Decisions;
using Sav.Domain.Policies;

namespace Sav.Application.Tests.Analyze;

public sealed class AnalyzeSqlUseCaseTests
{
    [Fact]
    public async Task ExecuteAsync_parses_evaluates_policy_and_redacts_response()
    {
        RecordingRedactor redactor = new();
        FakePathResolver paths = new();
        FakePolicyLoader policies = new();
        AnalyzeSqlUseCase useCase = new(
            new FakeParser(success: true),
            new FakePolicyEngine(PolicyOutcome.Allow),
            policies,
            new FakeContractLoader(),
            paths,
            redactor);

        AnalyzeSqlResponse response = await useCase.ExecuteAsync(
            new AnalyzeSqlRequest("SELECT id FROM users", "policies/demo.yaml", ContractPath: null),
            CancellationToken.None);

        Assert.Equal(PolicyOutcome.Allow, response.Decision.Outcome);
        Assert.True(response.Analysis.IsParsable);
        Assert.Contains("Select", response.Analysis.Ir.StatementTypes);
        Assert.False(response.EffectiveDisclosure.IncludeObjectNames);
        Assert.Equal(1, redactor.RedactObjectCalls);
        Assert.Equal(1, paths.ResolveCalls);
        Assert.Equal("policies/demo.yaml", paths.LastRelativePath);
        Assert.Equal(1, policies.LoadCalls);
        Assert.Contains(paths.LastResolvedPath, policies.LoadedPaths);
    }

    [Fact]
    public async Task ExecuteAsync_deny_unparsable_sql()
    {
        AnalyzeSqlUseCase useCase = new(
            new FakeParser(success: false),
            new FakePolicyEngine(PolicyOutcome.Deny, ["sql_unparsable"]),
            new FakePolicyLoader(),
            new FakeContractLoader(),
            new FakePathResolver(),
            new RecordingRedactor());

        AnalyzeSqlResponse response = await useCase.ExecuteAsync(
            new AnalyzeSqlRequest("SELEC 1", "policies/demo.yaml", null),
            CancellationToken.None);

        Assert.Equal(PolicyOutcome.Deny, response.Decision.Outcome);
        Assert.False(response.Analysis.IsParsable);
        Assert.Contains("sql_unparsable", response.RedactedReasons);
    }

    [Fact]
    public async Task ExecuteAsync_intersects_contract_disclosure_when_present()
    {
        FakePathResolver paths = new();
        FakeContractLoader contracts = new(
            new Contract(
                "c1",
                "1",
                [],
                new DisclosureProfile("open", true, true, true, true)));
        FakePolicyLoader policies = new(
            CreatePolicy(new DisclosureProfile("policy", true, false, true, false)));
        AnalyzeSqlUseCase useCase = new(
            new FakeParser(success: true),
            new FakePolicyEngine(PolicyOutcome.Allow),
            policies,
            contracts,
            paths,
            new RecordingRedactor());

        AnalyzeSqlResponse response = await useCase.ExecuteAsync(
            new AnalyzeSqlRequest("SELECT 1", "policies/demo.yaml", "contracts/demo.yaml"),
            CancellationToken.None);

        Assert.True(response.EffectiveDisclosure.IncludePlanSummary);
        Assert.False(response.EffectiveDisclosure.IncludeObjectNames);
        Assert.True(response.EffectiveDisclosure.IncludeTimings);
        Assert.False(response.EffectiveDisclosure.IncludeRowCounts);
        Assert.Equal(2, paths.ResolveCalls);
    }

    private static Policy CreatePolicy(DisclosureProfile disclosure) =>
        new(
            id: "p",
            version: "1",
            allowedStatementTypes: ["Select"],
            deniedTables: [],
            deniedColumns: [],
            allowedFunctions: [],
            denyUnresolvedObjects: false,
            denyMultipleStatements: true,
            denyUpdateDeleteWithoutPredicate: true,
            maxCostBucket: "high",
            forbiddenPlanNodes: [],
            disclosure: disclosure);
}
