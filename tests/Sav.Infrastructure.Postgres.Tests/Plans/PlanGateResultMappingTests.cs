using Sav.Domain.Plans;
using Sav.Domain.Policies;
using Sav.Infrastructure.Postgres.Plans;

namespace Sav.Infrastructure.Postgres.Tests.Plans;

public sealed class PlanGateResultMappingTests
{
    [Fact]
    public void Forbidden_node_maps_to_deny()
    {
        PlanSummary summary = new("low", ["Nested Loop"], []);
        PlanGateResult result = PlanNodePolicy.Evaluate(summary, Policy("extreme", ["Nested Loop"]));
        Assert.Equal(PlanGateOutcome.Deny, result.Outcome);
        Assert.Equal(["forbidden_plan_node"], result.Reasons);
        Assert.NotNull(result.Summary);
    }

    [Fact]
    public void Cost_over_max_maps_to_deny()
    {
        PlanSummary summary = new("high", ["Index Scan"], []);
        PlanGateResult result = PlanNodePolicy.Evaluate(summary, Policy("moderate", []));
        Assert.Equal(PlanGateOutcome.Deny, result.Outcome);
        Assert.Equal(["plan_cost_exceeded"], result.Reasons);
    }

    [Fact]
    public void Cost_at_limit_with_risk_maps_to_review()
    {
        PlanSummary summary = new("moderate", ["Seq Scan"], ["node:Seq Scan"]);
        PlanGateResult result = PlanNodePolicy.Evaluate(summary, Policy("moderate", []));
        Assert.Equal(PlanGateOutcome.Review, result.Outcome);
        Assert.Equal(["plan_cost_at_limit_with_risk"], result.Reasons);
    }

    [Fact]
    public void Allow_carries_bucketed_summary()
    {
        PlanSummary summary = new("low", ["Index Scan"], []);
        PlanGateResult result = PlanNodePolicy.Evaluate(summary, Policy("high", []));
        Assert.Equal(PlanGateOutcome.Allow, result.Outcome);
        Assert.Empty(result.Reasons);
        Assert.Same(summary, result.Summary);
    }

    [Theory]
    [InlineData(0, "trivial")]
    [InlineData(9.9, "trivial")]
    [InlineData(10, "low")]
    [InlineData(99, "low")]
    [InlineData(100, "moderate")]
    [InlineData(999, "moderate")]
    [InlineData(1000, "high")]
    [InlineData(9999, "high")]
    [InlineData(10000, "extreme")]
    public void Bucketer_closed_vocabulary(double cost, string expected)
    {
        Assert.Equal(expected, PlanBucketer.Bucketize(cost));
    }

    private static Policy Policy(string maxCost, IReadOnlyList<string> forbidden) =>
        new(
            "p",
            "1",
            ["Select"],
            [],
            [],
            [],
            true,
            true,
            true,
            maxCost,
            forbidden,
            new DisclosureProfile("strict", false, false, false, false));
}
