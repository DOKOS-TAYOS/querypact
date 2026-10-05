using System.Text.RegularExpressions;
using Sav.Domain.Errors;

namespace Sav.Infrastructure.Postgres.Oracle;

/// <summary>
/// MVP identifier gate: <c>^[a-z_][a-z0-9_]*$</c>, length ≤ 63, must appear in ColumnsRead (or caller-supplied allow list).
/// Mixed-case / quoted PostgreSQL identifiers fail closed.
/// </summary>
public static partial class PgIdentifierGuard
{
    private const int MaxLength = 63;

    public static string ValidateAndQuote(string identifier, IReadOnlyList<string> columnsRead)
    {
        ArgumentNullException.ThrowIfNull(columnsRead);

        if (string.IsNullOrEmpty(identifier) ||
            identifier.Length > MaxLength ||
            !SafeIdent().IsMatch(identifier))
        {
            throw new SavException(
                SavErrorCode.UnsafeIdentifier,
                "unsafe_identifier: identifier rejected by MVP gate.");
        }

        bool present = columnsRead.Any(c => string.Equals(c, identifier, StringComparison.Ordinal));
        if (!present)
        {
            throw new SavException(
                SavErrorCode.UnsafeIdentifier,
                "unsafe_identifier: identifier not present in columns read.");
        }

        return "\"" + identifier.Replace("\"", "\"\"", StringComparison.Ordinal) + "\"";
    }

    [GeneratedRegex("^[a-z_][a-z0-9_]*$", RegexOptions.CultureInvariant)]
    private static partial Regex SafeIdent();
}
