namespace Sav.Domain.Policies;

public sealed record Policy
{
    public Policy(
        string id,
        string version,
        IReadOnlyList<string> allowedStatementTypes,
        IReadOnlyList<string> deniedTables,
        IReadOnlyList<string> deniedColumns,
        IReadOnlyList<string> allowedFunctions,
        bool denyUnresolvedObjects,
        bool denyMultipleStatements,
        bool denyUpdateDeleteWithoutPredicate,
        string maxCostBucket,
        IReadOnlyList<string> forbiddenPlanNodes,
        DisclosureProfile disclosure)
    {
        ArgumentNullException.ThrowIfNull(allowedStatementTypes);
        ArgumentNullException.ThrowIfNull(deniedTables);
        ArgumentNullException.ThrowIfNull(deniedColumns);
        ArgumentNullException.ThrowIfNull(allowedFunctions);
        ArgumentNullException.ThrowIfNull(forbiddenPlanNodes);
        ArgumentNullException.ThrowIfNull(disclosure);

        Id = id;
        Version = version;
        AllowedStatementTypes = allowedStatementTypes.ToArray();
        DeniedTables = deniedTables.ToArray();
        DeniedColumns = deniedColumns.ToArray();
        AllowedFunctions = allowedFunctions.ToArray();
        DenyUnresolvedObjects = denyUnresolvedObjects;
        DenyMultipleStatements = denyMultipleStatements;
        DenyUpdateDeleteWithoutPredicate = denyUpdateDeleteWithoutPredicate;
        MaxCostBucket = maxCostBucket;
        ForbiddenPlanNodes = forbiddenPlanNodes.ToArray();
        Disclosure = disclosure;
    }

    public string Id { get; }

    public string Version { get; }

    public IReadOnlyList<string> AllowedStatementTypes { get; }

    public IReadOnlyList<string> DeniedTables { get; }

    public IReadOnlyList<string> DeniedColumns { get; }

    public IReadOnlyList<string> AllowedFunctions { get; }

    public bool DenyUnresolvedObjects { get; }

    public bool DenyMultipleStatements { get; }

    public bool DenyUpdateDeleteWithoutPredicate { get; }

    public string MaxCostBucket { get; }

    public IReadOnlyList<string> ForbiddenPlanNodes { get; }

    public DisclosureProfile Disclosure { get; }
}
