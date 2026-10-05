using Sav.Domain.Analysis;
using Sav.Domain.Decisions;
using Sav.Domain.Policies;

namespace Sav.Application.Abstractions;

public interface IPolicyEngine
{
    Task<PolicyDecision> EvaluateAsync(
        SqlAnalysis analysis,
        Policy policy,
        CancellationToken cancellationToken);
}
