namespace Sav.Domain.Schema;

public sealed record SchemaSnapshot
{
    public SchemaSnapshot(
        string schemaName,
        IReadOnlyDictionary<string, long> relationCountByRelkind,
        IReadOnlyDictionary<string, string> relationDigestByName,
        IReadOnlyDictionary<string, bool> constraintExistsByName,
        IReadOnlyDictionary<string, string>? constraintDigestByName = null,
        IReadOnlyDictionary<string, string>? relationKindByName = null)
    {
        ArgumentNullException.ThrowIfNull(relationCountByRelkind);
        ArgumentNullException.ThrowIfNull(relationDigestByName);
        ArgumentNullException.ThrowIfNull(constraintExistsByName);

        SchemaName = schemaName;
        RelationCountByRelkind = new Dictionary<string, long>(relationCountByRelkind);
        RelationDigestByName = new Dictionary<string, string>(relationDigestByName);
        ConstraintExistsByName = new Dictionary<string, bool>(constraintExistsByName);
        ConstraintDigestByName = new Dictionary<string, string>(
            constraintDigestByName ?? new Dictionary<string, string>());
        RelationKindByName = new Dictionary<string, string>(
            relationKindByName ?? new Dictionary<string, string>());
    }

    public string SchemaName { get; }

    public IReadOnlyDictionary<string, long> RelationCountByRelkind { get; }

    public IReadOnlyDictionary<string, string> RelationDigestByName { get; }

    public IReadOnlyDictionary<string, bool> ConstraintExistsByName { get; }

    public IReadOnlyDictionary<string, string> ConstraintDigestByName { get; }

    public IReadOnlyDictionary<string, string> RelationKindByName { get; }

    public bool Equals(SchemaSnapshot? other)
    {
        if (other is null)
        {
            return false;
        }

        if (ReferenceEquals(this, other))
        {
            return true;
        }

        return SchemaName == other.SchemaName
            && DictionaryEquals(RelationCountByRelkind, other.RelationCountByRelkind)
            && DictionaryEquals(RelationDigestByName, other.RelationDigestByName)
            && DictionaryEquals(ConstraintExistsByName, other.ConstraintExistsByName)
            && DictionaryEquals(ConstraintDigestByName, other.ConstraintDigestByName)
            && DictionaryEquals(RelationKindByName, other.RelationKindByName);
    }

    public override int GetHashCode()
    {
        HashCode hash = new();
        hash.Add(SchemaName);
        AddDictionaryHash(ref hash, RelationCountByRelkind);
        AddDictionaryHash(ref hash, RelationDigestByName);
        AddDictionaryHash(ref hash, ConstraintExistsByName);
        AddDictionaryHash(ref hash, ConstraintDigestByName);
        AddDictionaryHash(ref hash, RelationKindByName);
        return hash.ToHashCode();
    }

    private static bool DictionaryEquals<TValue>(
        IReadOnlyDictionary<string, TValue> left,
        IReadOnlyDictionary<string, TValue> right)
    {
        if (left.Count != right.Count)
        {
            return false;
        }

        foreach (KeyValuePair<string, TValue> pair in left)
        {
            if (!right.TryGetValue(pair.Key, out TValue? value))
            {
                return false;
            }

            if (!EqualityComparer<TValue>.Default.Equals(pair.Value, value))
            {
                return false;
            }
        }

        return true;
    }

    private static void AddDictionaryHash<TValue>(
        ref HashCode hash,
        IReadOnlyDictionary<string, TValue> dictionary)
    {
        foreach (string key in dictionary.Keys.OrderBy(static k => k, StringComparer.Ordinal))
        {
            hash.Add(key);
            hash.Add(dictionary[key]);
        }
    }
}
