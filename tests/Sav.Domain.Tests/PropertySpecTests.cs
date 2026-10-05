using Sav.Domain.Contracts;
using Sav.Domain.Policies;

namespace Sav.Domain.Tests;

public sealed class PropertySpecTests
{
    [Fact]
    public void QuerySucceedsSpec_uses_locked_property_name()
    {
        QuerySucceedsSpec spec = new();

        Assert.Equal("query_succeeds", spec.Name);
        Assert.IsAssignableFrom<PropertySpec>(spec);
    }

    [Fact]
    public void EmptyResultSpec_uses_locked_property_name()
    {
        EmptyResultSpec spec = new();

        Assert.Equal("empty_result", spec.Name);
        Assert.IsAssignableFrom<PropertySpec>(spec);
    }

    [Fact]
    public void Contract_RequiredProperties_accepts_mvp_a_specs_as_PropertySpec_list()
    {
        DisclosureProfile disclosure = DisclosureProfileMerge.StrictDefaults("contract");
        IReadOnlyList<PropertySpec> required =
        [
            new QuerySucceedsSpec(),
            new EmptyResultSpec(),
        ];

        Contract contract = new(
            id: "c1",
            version: "1.0.0",
            requiredProperties: required,
            disclosure: disclosure);

        Assert.Equal(2, contract.RequiredProperties.Count);
        Assert.All(contract.RequiredProperties, p => Assert.IsAssignableFrom<PropertySpec>(p));
        Assert.Equal("query_succeeds", contract.RequiredProperties[0].Name);
        Assert.Equal("empty_result", contract.RequiredProperties[1].Name);
    }

    [Fact]
    public void Contract_RequiredProperties_copies_input_collection()
    {
        List<PropertySpec> mutable = [new QuerySucceedsSpec()];
        Contract contract = new(
            id: "c1",
            version: "1.0.0",
            requiredProperties: mutable,
            disclosure: DisclosureProfileMerge.StrictDefaults());

        mutable.Add(new EmptyResultSpec());

        Assert.Single(contract.RequiredProperties);
    }

    [Fact]
    public void UniqueSpec_and_NonNullSpec_use_locked_property_names()
    {
        UniqueSpec unique = new("code");
        NonNullSpec nonNull = new("code");

        Assert.Equal("unique", unique.Name);
        Assert.Equal("code", unique.Column);
        Assert.Equal("non_null", nonNull.Name);
        Assert.Equal("code", nonNull.Column);
    }

    [Fact]
    public void AffectedRowsSpec_and_QueryEquivalentSpec_use_locked_property_names()
    {
        AffectedRowsSpec affected = new(1, 10);
        QueryEquivalentSpec equivalent = new();

        Assert.Equal("affected_rows", affected.Name);
        Assert.Equal(1, affected.MinInclusive);
        Assert.Equal(10, affected.MaxInclusive);
        Assert.Equal("query_equivalent", equivalent.Name);
    }

    [Fact]
    public void SchemaInvariantSpec_and_NoNewOrphansSpec_use_locked_property_names()
    {
        SchemaInvariantSpec schema = new(
        [
            new SchemaInvariantRequirement("orders", "r"),
        ]);
        NoNewOrphansSpec orphans = new("orders", "id", "order_items", "order_id");

        Assert.Equal("schema_invariant", schema.Name);
        Assert.Single(schema.Requirements);
        Assert.Equal("orders", schema.Requirements[0].RelationName);
        Assert.Equal("no_new_orphans", orphans.Name);
        Assert.Equal("order_items", orphans.ChildTable);
    }
}
