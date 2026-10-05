using Sav.Domain.Schema;

namespace Sav.Domain.Tests;

public static class SchemaSnapshotFixtures
{
    public static SchemaSnapshot CreateSynthetic(
        string schemaName,
        IReadOnlyDictionary<string, long>? relationCountByRelkind = null,
        IReadOnlyDictionary<string, string>? relationDigestByName = null,
        IReadOnlyDictionary<string, bool>? constraintExistsByName = null,
        IReadOnlyDictionary<string, string>? relationKindByName = null)
    {
        return new SchemaSnapshot(
            schemaName,
            relationCountByRelkind ?? new Dictionary<string, long>
            {
                ["r"] = 2,
                ["i"] = 1,
            },
            relationDigestByName ?? new Dictionary<string, string>
            {
                ["public.orders"] = "digest-orders-v1",
                ["public.order_items"] = "digest-items-v1",
            },
            constraintExistsByName ?? new Dictionary<string, bool>
            {
                ["orders_pkey"] = true,
                ["order_items_orders_fkey"] = true,
            },
            relationKindByName: relationKindByName ?? new Dictionary<string, string>
            {
                ["public.orders"] = "r",
                ["public.order_items"] = "r",
            });
    }

    public static SchemaSnapshot WithRelationCount(
        SchemaSnapshot baseline,
        string relkind,
        long count)
    {
        Dictionary<string, long> counts = baseline.RelationCountByRelkind.ToDictionary(
            static pair => pair.Key,
            static pair => pair.Value);
        counts[relkind] = count;

        return new SchemaSnapshot(
            baseline.SchemaName,
            counts,
            baseline.RelationDigestByName,
            baseline.ConstraintExistsByName,
            relationKindByName: baseline.RelationKindByName);
    }

    public static SchemaSnapshot WithRelationDigest(
        SchemaSnapshot baseline,
        string relationName,
        string digest)
    {
        Dictionary<string, string> digests = baseline.RelationDigestByName.ToDictionary(
            static pair => pair.Key,
            static pair => pair.Value);
        digests[relationName] = digest;

        return new SchemaSnapshot(
            baseline.SchemaName,
            baseline.RelationCountByRelkind,
            digests,
            baseline.ConstraintExistsByName,
            relationKindByName: baseline.RelationKindByName);
    }
}
