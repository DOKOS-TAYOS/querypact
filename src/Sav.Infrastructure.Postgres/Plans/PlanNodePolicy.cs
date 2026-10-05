using Sav.Domain.Plans;
using Sav.Domain.Policies;

namespace Sav.Infrastructure.Postgres.Plans;

/// <summary>
/// Applies Policy.MaxCostBucket / ForbiddenPlanNodes to a bucketed plan summary.
/// </summary>
public static class PlanNodePolicy
{
    public static PlanGateResult Evaluate(PlanSummary summary, Policy policy)
    {
        ArgumentNullException.ThrowIfNull(summary);
        ArgumentNullException.ThrowIfNull(policy);

        foreach (string node in summary.NodeTypes)
        {
            if (policy.ForbiddenPlanNodes.Contains(node, StringComparer.Ordinal))
            {
                return new PlanGateResult(
                    PlanGateOutcome.Deny,
                    ["forbidden_plan_node"],
                    summary);
            }
        }

        int costOrdinal = PlanBucketer.Ordinal(summary.CostBucket);
        int maxOrdinal = PlanBucketer.Ordinal(policy.MaxCostBucket);

        if (costOrdinal > maxOrdinal)
        {
            return new PlanGateResult(
                PlanGateOutcome.Deny,
                ["plan_cost_exceeded"],
                summary);
        }

        if (costOrdinal == maxOrdinal && summary.RiskFlags.Count > 0)
        {
            return new PlanGateResult(
                PlanGateOutcome.Review,
                ["plan_cost_at_limit_with_risk"],
                summary);
        }

        return new PlanGateResult(PlanGateOutcome.Allow, [], summary);
    }
}
