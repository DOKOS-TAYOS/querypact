namespace Sav.Domain.Contracts;

public abstract record PropertySpec(string Name);

public sealed record QuerySucceedsSpec() : PropertySpec("query_succeeds");

public sealed record EmptyResultSpec() : PropertySpec("empty_result");

public sealed record UniqueSpec(string Column) : PropertySpec("unique");

public sealed record NonNullSpec(string Column) : PropertySpec("non_null");

public sealed record AffectedRowsSpec(long MinInclusive, long? MaxInclusive) : PropertySpec("affected_rows");

public sealed record QueryEquivalentSpec() : PropertySpec("query_equivalent");

public sealed record SchemaInvariantSpec : PropertySpec
{
    public SchemaInvariantSpec(IReadOnlyList<SchemaInvariantRequirement> requirements)
        : base("schema_invariant")
    {
        ArgumentNullException.ThrowIfNull(requirements);
        Requirements = requirements.ToArray();
    }

    public IReadOnlyList<SchemaInvariantRequirement> Requirements { get; }
}

public sealed record NoNewOrphansSpec(
    string ParentTable,
    string ParentKey,
    string ChildTable,
    string ChildKey) : PropertySpec("no_new_orphans");
