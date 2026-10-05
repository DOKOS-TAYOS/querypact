using System.Text.RegularExpressions;

namespace Sav.Infrastructure.Postgres.Catalog;

internal static partial class PgCatalogObjectName
{
    public static bool TryParse(
        string objectName,
        out string? schema,
        out string relation)
    {
        schema = null;
        relation = string.Empty;
        if (string.IsNullOrWhiteSpace(objectName))
        {
            return false;
        }

        string trimmed = objectName.Trim();
        int dot = trimmed.IndexOf('.', StringComparison.Ordinal);
        if (dot < 0)
        {
            if (!SafeIdent().IsMatch(trimmed))
            {
                return false;
            }

            relation = trimmed;
            return true;
        }

        string left = trimmed[..dot];
        string right = trimmed[(dot + 1)..];
        if (!SafeIdent().IsMatch(left) || !SafeIdent().IsMatch(right))
        {
            return false;
        }

        schema = left;
        relation = right;
        return true;
    }

    public static string EscapeLiteral(string value) =>
        value.Replace("'", "''", StringComparison.Ordinal);

    public static string QuoteIdentifier(string value) =>
        "\"" + value.Replace("\"", "\"\"", StringComparison.Ordinal) + "\"";

    [GeneratedRegex("^[A-Za-z_][A-Za-z0-9_]*$", RegexOptions.CultureInvariant)]
    private static partial Regex SafeIdent();
}
