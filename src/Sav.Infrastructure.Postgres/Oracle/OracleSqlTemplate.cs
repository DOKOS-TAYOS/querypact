using Sav.Application.Abstractions;

namespace Sav.Infrastructure.Postgres.Oracle;

/// <summary>
/// Oracle SQL templates including MVP-B schema/orphan markers.
/// </summary>
public enum OracleSqlTemplateKind
{
    QuerySucceedsExists,
    EmptyResultNotExists,
    UniqueDistinctCount,
    NonNullIsNullCount,
    QueryEquivalentExceptLeft,
    QueryEquivalentExceptRight,
    AffectedRowsDirectDml,
}

public static class OracleSqlTemplate
{
    public static OracleScalarColumn BoolVColumn { get; } =
        new("v", OracleScalarKind.BoolV);

    public static OracleScalarColumn LongVColumn { get; } =
        new("v", OracleScalarKind.LongV);

    public static string Wrap(
        OracleSqlTemplateKind kind,
        string agentSelect,
        string? quotedIdentifier = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(agentSelect);

        return kind switch
        {
            OracleSqlTemplateKind.QuerySucceedsExists =>
                "SELECT COUNT(q)::bigint AS v FROM ( " + agentSelect + " ) AS q",
            OracleSqlTemplateKind.EmptyResultNotExists =>
                "SELECT NOT EXISTS (SELECT 1 FROM ( " + agentSelect + " ) AS q) AS v",
            OracleSqlTemplateKind.UniqueDistinctCount =>
                WrapWithColumn(
                    quotedIdentifier,
                    "SELECT COUNT(*)::bigint AS v FROM ( " + agentSelect
                    + " ) AS q HAVING COUNT(" + quotedIdentifier + ") <> COUNT(DISTINCT "
                    + quotedIdentifier + ")"),
            OracleSqlTemplateKind.NonNullIsNullCount =>
                WrapWithColumn(
                    quotedIdentifier,
                    "SELECT COUNT(*)::bigint AS v FROM ( " + agentSelect
                    + " ) AS q WHERE " + quotedIdentifier + " IS NULL"),
            OracleSqlTemplateKind.AffectedRowsDirectDml =>
                agentSelect.Trim(),
            _ => throw new ArgumentOutOfRangeException(nameof(kind), kind, "Unknown oracle template."),
        };
    }

    public static string WrapExceptAll(OracleSqlTemplateKind kind, string leftSelect, string rightSelect)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(leftSelect);
        ArgumentException.ThrowIfNullOrWhiteSpace(rightSelect);

        string left = leftSelect.Trim();
        string right = rightSelect.Trim();

        return kind switch
        {
            OracleSqlTemplateKind.QueryEquivalentExceptLeft =>
                "SELECT COUNT(*)::bigint AS v FROM ( ( " + left + " ) EXCEPT ALL ( " + right + " ) ) AS diff",
            OracleSqlTemplateKind.QueryEquivalentExceptRight =>
                "SELECT COUNT(*)::bigint AS v FROM ( ( " + right + " ) EXCEPT ALL ( " + left + " ) ) AS diff",
            _ => throw new ArgumentOutOfRangeException(nameof(kind), kind, "Not an equivalence template."),
        };
    }

    /// <summary>
    /// Fixed <c>no_new_orphans</c> count template. Identifiers must already be quoted.
    /// </summary>
    public static string WrapNoNewOrphans(
        string quotedChildTable,
        string quotedParentTable,
        string quotedParentKey,
        string quotedChildKey)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(quotedChildTable);
        ArgumentException.ThrowIfNullOrWhiteSpace(quotedParentTable);
        ArgumentException.ThrowIfNullOrWhiteSpace(quotedParentKey);
        ArgumentException.ThrowIfNullOrWhiteSpace(quotedChildKey);

        return "SELECT COUNT(*)::bigint AS v FROM " + quotedChildTable
            + " c WHERE c." + quotedChildKey + " IS DISTINCT FROM NULL"
            + " AND NOT EXISTS ( SELECT 1 FROM " + quotedParentTable
            + " p WHERE p." + quotedParentKey + " = c." + quotedChildKey + " )";
    }

    private static string WrapWithColumn(string? quotedIdentifier, string sql)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(quotedIdentifier);
        return sql;
    }
}
