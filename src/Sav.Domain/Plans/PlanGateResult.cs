namespace Sav.Domain.Plans;

public sealed record PlanGateResult
{
    public PlanGateResult(
        PlanGateOutcome outcome,
        IReadOnlyList<string> reasons,
        PlanSummary? summary)
    {
        ArgumentNullException.ThrowIfNull(reasons);
        Outcome = outcome;
        Reasons = reasons.ToArray();
        Summary = summary;
    }

    public PlanGateOutcome Outcome { get; }

    public IReadOnlyList<string> Reasons { get; }

    public PlanSummary? Summary { get; }
}
