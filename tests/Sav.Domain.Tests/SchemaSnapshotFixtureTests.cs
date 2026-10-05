using Sav.Domain.Schema;

namespace Sav.Domain.Tests;

public sealed class SchemaSnapshotFixtureTests
{
    [Fact]
    public void CreateSynthetic_before_and_after_match_when_unchanged()
    {
        SchemaSnapshot before = SchemaSnapshotFixtures.CreateSynthetic("public");
        SchemaSnapshot after = SchemaSnapshotFixtures.CreateSynthetic("public");

        Assert.Equal(before, after);
    }

    [Fact]
    public void After_snapshot_differs_only_on_intended_relation_count()
    {
        SchemaSnapshot before = SchemaSnapshotFixtures.CreateSynthetic("public");
        SchemaSnapshot after = SchemaSnapshotFixtures.WithRelationCount(before, "r", 3);

        Assert.NotEqual(before, after);
        Assert.Equal(before.SchemaName, after.SchemaName);
        Assert.Equal(before.RelationDigestByName, after.RelationDigestByName);
        Assert.Equal(before.RelationKindByName, after.RelationKindByName);
        Assert.Equal(before.ConstraintExistsByName, after.ConstraintExistsByName);
        Assert.Equal(2, before.RelationCountByRelkind["r"]);
        Assert.Equal(3, after.RelationCountByRelkind["r"]);
    }

    [Fact]
    public void After_snapshot_differs_only_on_intended_relation_digest()
    {
        SchemaSnapshot before = SchemaSnapshotFixtures.CreateSynthetic("public");
        SchemaSnapshot after = SchemaSnapshotFixtures.WithRelationDigest(
            before,
            "public.orders",
            "digest-orders-v2");

        Assert.NotEqual(before, after);
        Assert.Equal(before.RelationCountByRelkind, after.RelationCountByRelkind);
        Assert.Equal(before.RelationKindByName, after.RelationKindByName);
        Assert.Equal(before.ConstraintExistsByName, after.ConstraintExistsByName);
        Assert.Equal("digest-orders-v1", before.RelationDigestByName["public.orders"]);
        Assert.Equal("digest-orders-v2", after.RelationDigestByName["public.orders"]);
        Assert.Equal(
            before.RelationDigestByName["public.order_items"],
            after.RelationDigestByName["public.order_items"]);
    }

    [Fact]
    public void SchemaSnapshot_constructor_copies_dictionaries()
    {
        Dictionary<string, long> counts = new() { ["r"] = 1 };
        Dictionary<string, string> digests = new() { ["t"] = "d1" };
        Dictionary<string, bool> constraints = new() { ["c"] = true };
        Dictionary<string, string> kinds = new() { ["t"] = "r" };

        SchemaSnapshot snapshot = new(
            "public",
            counts,
            digests,
            constraints,
            relationKindByName: kinds);
        counts["r"] = 99;
        digests["t"] = "mutated";
        constraints["c"] = false;
        kinds["t"] = "v";

        Assert.Equal(1, snapshot.RelationCountByRelkind["r"]);
        Assert.Equal("d1", snapshot.RelationDigestByName["t"]);
        Assert.True(snapshot.ConstraintExistsByName["c"]);
        Assert.Equal("r", snapshot.RelationKindByName["t"]);
    }
}
