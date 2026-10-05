namespace Sav.Domain.Plans;

public sealed record PlanSummary
{
    public PlanSummary(
        string costBucket,
        IReadOnlyList<string> nodeTypes,
        IReadOnlyList<string> riskFlags)
    {
        ArgumentNullException.ThrowIfNull(nodeTypes);
        ArgumentNullException.ThrowIfNull(riskFlags);
        CostBucket = costBucket;
        NodeTypes = nodeTypes.ToArray();
        RiskFlags = riskFlags.ToArray();
    }

    public string CostBucket { get; }

    public IReadOnlyList<string> NodeTypes { get; }

    public IReadOnlyList<string> RiskFlags { get; }
}
