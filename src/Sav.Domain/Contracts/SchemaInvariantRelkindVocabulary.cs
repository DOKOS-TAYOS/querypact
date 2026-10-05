namespace Sav.Domain.Contracts;

/// <summary>
/// Closed PostgreSQL relation-kind vocabulary that schema snapshots can represent with
/// both a relation digest and a per-kind count.
/// </summary>
public static class SchemaInvariantRelkindVocabulary
{
    private static readonly HashSet<string> Values = new(StringComparer.Ordinal)
    {
        "r",
        "S",
        "v",
        "m",
        "c",
        "t",
        "f",
        "p",
    };

    public static bool IsSupported(string? relkind) =>
        !string.IsNullOrWhiteSpace(relkind) && Values.Contains(relkind);
}
