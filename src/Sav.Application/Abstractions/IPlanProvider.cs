using Sav.Domain.Decisions;
using Sav.Domain.Plans;
using Sav.Domain.Policies;
using Sav.Domain.Targets;

namespace Sav.Application.Abstractions;

/// <summary>
/// Plan gate. Skips EXPLAIN when decision is Deny or Review.
/// On Allow, session is required and must come from the pipeline.
/// </summary>
public interface IPlanProvider
{
    Task<PlanGateResult> GetEstimatedPlanAsync(
        TargetAlias target,
        string sql,
        PolicyDecision decision,
        Policy policy,
        IReadOnlySession? session,
        CancellationToken cancellationToken);
}
