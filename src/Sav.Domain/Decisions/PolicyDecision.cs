namespace Sav.Domain.Decisions;

public sealed record PolicyDecision
{
    public PolicyDecision(
        PolicyOutcome outcome,
        IReadOnlyList<string> reasons,
        IReadOnlyList<string> ruleIds)
    {
        ArgumentNullException.ThrowIfNull(reasons);
        ArgumentNullException.ThrowIfNull(ruleIds);
        Outcome = outcome;
        Reasons = reasons.ToArray();
        RuleIds = ruleIds.ToArray();
    }

    public PolicyOutcome Outcome { get; }

    public IReadOnlyList<string> Reasons { get; }

    public IReadOnlyList<string> RuleIds { get; }
}
