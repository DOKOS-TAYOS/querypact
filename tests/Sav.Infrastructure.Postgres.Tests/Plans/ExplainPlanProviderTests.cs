using Sav.Application.Abstractions;
using Sav.Domain.Decisions;
using Sav.Domain.Errors;
using Sav.Domain.Plans;
using Sav.Domain.Policies;
using Sav.Domain.Targets;
using Sav.Infrastructure.Postgres.Plans;
using Sav.Infrastructure.Postgres.Targets;
using Sav.Infrastructure.Postgres.Tests.Fixtures;

namespace Sav.Infrastructure.Postgres.Tests.Plans;

[Collection(nameof(PostgresRoCollection))]
public sealed class ExplainPlanProviderTests
{
    private readonly PostgresRoFixture _fixture;

    public ExplainPlanProviderTests(PostgresRoFixture fixture)
    {
        _fixture = fixture;
    }

    [Fact]
    public async Task Allow_runs_explain_format_json_without_analyze()
    {
        await using ReadOnlySessionFactory factory = _fixture.CreateFactory();
        TargetAlias alias = _fixture.Resolve(PostgresRoFixture.RoAlias);
        await using IReadOnlySession session =
            await factory.OpenReadOnlySessionAsync(alias, CancellationToken.None);

        ExplainPlanProvider provider = new(_fixture.Redactor);
        Policy policy = CreatePolicy(maxCostBucket: "extreme", forbidden: []);
        PlanGateResult result = await provider.GetEstimatedPlanAsync(
            alias,
            "SELECT id, payload FROM public.plan_items WHERE id = 1",
            new PolicyDecision(PolicyOutcome.Allow, [], []),
            policy,
            session,
            CancellationToken.None);

        Assert.Equal(PlanGateOutcome.Allow, result.Outcome);
        Assert.NotNull(result.Summary);
        AssertSourceNeverUsesExplainAnalyze();
    }

    [Fact]
    public async Task Timeout_is_typed_and_redacted()
    {
        await using ReadOnlySessionFactory factory = _fixture.CreateFactory(
            new ReadOnlySessionOptions
            {
                Disclosure = _fixture.StrictDisclosure,
                StatementTimeout = TimeSpan.FromMilliseconds(50),
                LockTimeout = TimeSpan.FromMilliseconds(50),
            });
        TargetAlias alias = _fixture.Resolve(PostgresRoFixture.RoAlias);
        await using IReadOnlySession session =
            await factory.OpenReadOnlySessionAsync(alias, CancellationToken.None);

        SavException ex = await Assert.ThrowsAsync<SavException>(
            () => session.ExecuteAsync("SELECT pg_sleep(2)", CancellationToken.None));

        Assert.Equal(SavErrorCode.QueryFailed, ex.Code);
        Assert.DoesNotContain("Password=", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("ro_password", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Cancellation_is_honored()
    {
        await using ReadOnlySessionFactory factory = _fixture.CreateFactory();
        TargetAlias alias = _fixture.Resolve(PostgresRoFixture.RoAlias);
        await using IReadOnlySession session =
            await factory.OpenReadOnlySessionAsync(alias, CancellationToken.None);

        ExplainPlanProvider provider = new(_fixture.Redactor);
        using CancellationTokenSource cts = new();
        await cts.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => provider.GetEstimatedPlanAsync(
            alias,
            "SELECT 1",
            new PolicyDecision(PolicyOutcome.Allow, [], []),
            CreatePolicy("extreme", []),
            session,
            cts.Token));
    }

    [Fact]
    public async Task Forbidden_node_denies()
    {
        await using ReadOnlySessionFactory factory = _fixture.CreateFactory();
        TargetAlias alias = _fixture.Resolve(PostgresRoFixture.RoAlias);
        await using IReadOnlySession session =
            await factory.OpenReadOnlySessionAsync(alias, CancellationToken.None);

        ExplainPlanProvider provider = new(_fixture.Redactor);
        Policy policy = CreatePolicy("extreme", ["Seq Scan"]);

        PlanGateResult result = await provider.GetEstimatedPlanAsync(
            alias,
            "SELECT payload FROM public.plan_items",
            new PolicyDecision(PolicyOutcome.Allow, [], []),
            policy,
            session,
            CancellationToken.None);

        Assert.Equal(PlanGateOutcome.Deny, result.Outcome);
        Assert.Contains("forbidden_plan_node", result.Reasons);
    }

    [Fact]
    public void Unknown_but_valid_plan_node_remains_visible_to_forbidden_node_policy()
    {
        const string explainJson =
            """
            [
              {
                "Plan": {
                  "Node Type": "Foreign Scan",
                  "Total Cost": 1.0
                }
              }
            ]
            """;

        PlanSummary summary = ExplainPlanProvider.ParseAndBucket(
            explainJson,
            new DisclosureProfile("strict", false, false, false, false));
        Policy policy = CreatePolicy("extreme", ["Foreign Scan"]);

        PlanGateResult result = PlanNodePolicy.Evaluate(summary, policy);

        Assert.Contains("Foreign Scan", summary.NodeTypes);
        Assert.Equal(PlanGateOutcome.Deny, result.Outcome);
        Assert.Contains("forbidden_plan_node", result.Reasons);
    }

    [Fact]
    public async Task Excessive_cost_denies()
    {
        PlanSummary summary = new("extreme", ["Seq Scan"], []);
        Policy policy = CreatePolicy("low", []);
        PlanGateResult result = PlanNodePolicy.Evaluate(summary, policy);
        Assert.Equal(PlanGateOutcome.Deny, result.Outcome);
        Assert.Contains("plan_cost_exceeded", result.Reasons);
    }

    private static void AssertSourceNeverUsesExplainAnalyze()
    {
        string? path = Directory
            .EnumerateFiles(
                FindRepoRoot(),
                "ExplainPlanProvider.cs",
                SearchOption.AllDirectories)
            .FirstOrDefault();
        Assert.NotNull(path);
        string text = File.ReadAllText(path!);
        Assert.Contains("EXPLAIN (FORMAT JSON)", text, StringComparison.Ordinal);
        Assert.DoesNotContain("EXPLAIN (ANALYZE", text, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("EXPLAIN ANALYZE", text, StringComparison.OrdinalIgnoreCase);
    }

    private static string FindRepoRoot()
    {
        DirectoryInfo? dir = new(AppContext.BaseDirectory);
        while (dir is not null)
        {
            if (File.Exists(Path.Combine(dir.FullName, "QueryPact.sln")))
            {
                return dir.FullName;
            }

            dir = dir.Parent;
        }

        return AppContext.BaseDirectory;
    }

    private static Policy CreatePolicy(string maxCostBucket, IReadOnlyList<string> forbidden)
    {
        return new Policy(
            "plan-test",
            "1",
            ["Select"],
            [],
            [],
            [],
            true,
            true,
            true,
            maxCostBucket,
            forbidden,
            new DisclosureProfile("strict", false, false, false, false));
    }
}
