using System.Text;
using Sav.Application.Abstractions;
using Sav.Domain.Analysis;
using Sav.Domain.Errors;
using Sav.Domain.Policies;

namespace Sav.Infrastructure.Postgres.Oracle;

/// <summary>
/// Closed SQL boundary: agent SQL is never a top-level command on a real alias;
/// QueryPact wraps only inside fixed <see cref="OracleSqlTemplate"/> forms.
/// </summary>
public static partial class OracleSqlBoundary
{
    private static readonly HashSet<string> AllowedSelectTypes =
        new(StringComparer.OrdinalIgnoreCase) { "Select" };

    private static readonly string[] DangerousSqlMarkers =
    [
        " into ",
        " copy ",
        " perform ",
        " explain ",
        " execute ",
        " prepare ",
        " create ",
        " alter ",
        " drop ",
        " insert ",
        " update ",
        " delete ",
        " truncate ",
        " grant ",
        " revoke ",
        " call ",
    ];

    public static string BuildWrappedCommand(
        OracleSqlTemplateKind kind,
        SqlIr ir,
        string agentSql,
        IReadOnlyList<string> policyAllowedFunctions,
        string? propertyColumn = null)
    {
        ArgumentNullException.ThrowIfNull(ir);
        ArgumentException.ThrowIfNullOrWhiteSpace(agentSql);
        ArgumentNullException.ThrowIfNull(policyAllowedFunctions);

        EnsureAgentSqlSafeForWrap(ir, agentSql, policyAllowedFunctions);

        string? quoted = null;
        if (propertyColumn is not null)
        {
            IReadOnlyList<string> allowColumns = BuildIdentifierAllowList(ir, propertyColumn);
            quoted = PgIdentifierGuard.ValidateAndQuote(propertyColumn, allowColumns);
        }

        return OracleSqlTemplate.Wrap(kind, agentSql.Trim(), quoted);
    }

    /// <summary>
    /// Validates left/right SELECTs for <c>query_equivalent</c> (both directions use EXCEPT ALL wrappers).
    /// </summary>
    public static void EnsureEquivalentSelectPairSafe(
        SqlIr leftIr,
        SqlIr rightIr,
        string leftSql,
        string rightSql,
        IReadOnlyList<string> policyAllowedFunctions)
    {
        EnsureAgentSqlSafeForWrap(leftIr, leftSql, policyAllowedFunctions);
        EnsureAgentSqlSafeForWrap(rightIr, rightSql, policyAllowedFunctions);
    }

    /// <summary>
    /// Ephemeral-only DML: no SELECT wrapper; rejects multi-statement text.
    /// </summary>
    public static string BuildAffectedRowsCommand(string agentDml)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(agentDml);

        string trimmed = agentDml.Trim();
        if (trimmed.Contains(';', StringComparison.Ordinal))
        {
            ThrowUnsupported();
        }

        return OracleSqlTemplate.Wrap(OracleSqlTemplateKind.AffectedRowsDirectDml, trimmed);
    }

    /// <summary>
    /// Builds fixed <c>no_new_orphans</c> COUNT SQL after identifier gate on all four keys.
    /// </summary>
    public static string BuildNoNewOrphansCommand(
        string parentTable,
        string parentKey,
        string childTable,
        string childKey)
    {
        string[] allow = [parentTable, parentKey, childTable, childKey];
        string quotedParent = PgIdentifierGuard.ValidateAndQuote(parentTable, allow);
        string quotedParentKey = PgIdentifierGuard.ValidateAndQuote(parentKey, allow);
        string quotedChild = PgIdentifierGuard.ValidateAndQuote(childTable, allow);
        string quotedChildKey = PgIdentifierGuard.ValidateAndQuote(childKey, allow);

        return OracleSqlTemplate.WrapNoNewOrphans(
            quotedChild,
            quotedParent,
            quotedParentKey,
            quotedChildKey);
    }

    private static IReadOnlyList<string> BuildIdentifierAllowList(SqlIr ir, string propertyColumn)
    {
        // Column must appear in IR ColumnsRead, or match the typed PropertySpec field (already passed as propertyColumn).
        if (ir.ColumnsRead.Any(c => string.Equals(c, propertyColumn, StringComparison.Ordinal)))
        {
            return ir.ColumnsRead;
        }

        return ir.ColumnsRead.Concat([propertyColumn]).ToArray();
    }

    public static void EnsureAgentSqlSafeForWrap(
        SqlIr ir,
        string agentSql,
        IReadOnlyList<string> policyAllowedFunctions)
    {
        ArgumentNullException.ThrowIfNull(ir);
        ArgumentException.ThrowIfNullOrWhiteSpace(agentSql);
        ArgumentNullException.ThrowIfNull(policyAllowedFunctions);

        if (ir.HasMultipleStatements || ir.StatementTypes.Count != 1)
        {
            ThrowUnsupported();
        }

        if (ir.HasDynamicSql)
        {
            ThrowUnsupported();
        }

        string statementType = ir.StatementTypes[0];
        if (!AllowedSelectTypes.Contains(statementType))
        {
            ThrowUnsupported();
        }

        if (ir.TablesWritten.Count > 0 || ir.ColumnsWritten.Count > 0)
        {
            ThrowUnsupported();
        }

        if (ir.RiskCodes.Any(c => string.Equals(c, "unsupported_construct", StringComparison.Ordinal)))
        {
            ThrowUnsupported();
        }

        EnsureFunctionsAllowed(ir, policyAllowedFunctions);
        EnsureNoDangerousMarkers(agentSql);
    }

    public static string RedactEgress(IRedactor redactor, DisclosureProfile profile, string value)
    {
        ArgumentNullException.ThrowIfNull(redactor);
        ArgumentNullException.ThrowIfNull(profile);
        return redactor.RedactText(value ?? string.Empty, profile);
    }

    private static void EnsureFunctionsAllowed(SqlIr ir, IReadOnlyList<string> policyAllowedFunctions)
    {
        if (ir.Functions.Count == 0)
        {
            return;
        }

        // Empty policy allow-list ⇒ deny every agent function call.
        if (policyAllowedFunctions.Count == 0)
        {
            ThrowUnsupported();
        }

        foreach (string function in ir.Functions)
        {
            bool inPolicy = policyAllowedFunctions.Any(
                a => string.Equals(a, function, StringComparison.Ordinal));
            if (!inPolicy)
            {
                ThrowUnsupported();
            }

            // Frozen wrapper builtin allow-list is empty: never treat catalog/extension funcs as builtins.
            if (OracleWrapperBuiltinFunctionAllowList.IsAllowed(function))
            {
                // Unreachable while allow-list remains empty; keep fail-closed if list ever drifts.
                continue;
            }
        }
    }

    private static void EnsureNoDangerousMarkers(string agentSql)
    {
        // Defense-in-depth only: inspect executable SQL text, not comments, literals, or quoted identifiers.
        string normalized = NormalizeExecutableSql(agentSql);
        foreach (string marker in DangerousSqlMarkers)
        {
            string verb = marker.Trim();
            if (normalized.Contains(" " + verb + " ", StringComparison.Ordinal)
                || normalized.Contains("(" + verb + " ", StringComparison.Ordinal)
                || normalized.Contains(" " + verb + "(", StringComparison.Ordinal)
                || normalized.Contains("(" + verb + "(", StringComparison.Ordinal))
            {
                ThrowUnsupported();
            }
        }

        if (normalized.Contains(';', StringComparison.Ordinal))
        {
            ThrowUnsupported();
        }
    }

    private static string NormalizeExecutableSql(string sql)
    {
        StringBuilder normalized = new(sql.Length + 2);
        normalized.Append(' ');

        for (int i = 0; i < sql.Length;)
        {
            char current = sql[i];

            if (char.IsWhiteSpace(current))
            {
                normalized.Append(' ');
                i++;
                continue;
            }

            if (current == '-' && i + 1 < sql.Length && sql[i + 1] == '-')
            {
                normalized.Append(' ');
                i += 2;
                while (i < sql.Length && sql[i] is not '\r' and not '\n')
                {
                    i++;
                }

                continue;
            }

            if (current == '/' && i + 1 < sql.Length && sql[i + 1] == '*')
            {
                normalized.Append(' ');
                i = SkipBlockComment(sql, i);
                if (i < 0)
                {
                    ThrowUnsupported();
                }

                continue;
            }

            if (current == '\'')
            {
                normalized.Append(' ');
                i = SkipSingleQuotedLiteral(sql, i, HasEscapeStringPrefix(sql, i));
                if (i < 0)
                {
                    ThrowUnsupported();
                }

                continue;
            }

            if (current == '"')
            {
                normalized.Append(' ');
                i = SkipDoubleQuotedIdentifier(sql, i);
                if (i < 0)
                {
                    ThrowUnsupported();
                }

                continue;
            }

            if (current == (char)36 &&
                (i == 0 || !IsIdentifierPart(sql[i - 1])) &&
                TryGetDollarQuoteDelimiter(sql, i, out string delimiter))
            {
                int closing = sql.IndexOf(
                    delimiter,
                    i + delimiter.Length,
                    StringComparison.Ordinal);
                if (closing < 0)
                {
                    ThrowUnsupported();
                }

                normalized.Append(' ');
                i = closing + delimiter.Length;
                continue;
            }

            normalized.Append(char.ToLowerInvariant(current));
            i++;
        }

        normalized.Append(' ');
        return normalized.ToString();
    }

    private static int SkipBlockComment(string sql, int start)
    {
        int depth = 1;
        int i = start + 2;
        while (i < sql.Length && depth > 0)
        {
            if (i + 1 < sql.Length && sql[i] == '/' && sql[i + 1] == '*')
            {
                depth++;
                i += 2;
            }
            else if (i + 1 < sql.Length && sql[i] == '*' && sql[i + 1] == '/')
            {
                depth--;
                i += 2;
            }
            else
            {
                i++;
            }
        }

        return depth == 0 ? i : -1;
    }

    private static int SkipSingleQuotedLiteral(string sql, int start, bool backslashEscapes)
    {
        int i = start + 1;
        while (i < sql.Length)
        {
            if (sql[i] == '\'')
            {
                if (i + 1 < sql.Length && sql[i + 1] == '\'')
                {
                    i += 2;
                    continue;
                }

                return i + 1;
            }

            if (backslashEscapes && sql[i] == '\\' && i + 1 < sql.Length)
            {
                i += 2;
                continue;
            }

            i++;
        }

        return -1;
    }

    private static int SkipDoubleQuotedIdentifier(string sql, int start)
    {
        int i = start + 1;
        while (i < sql.Length)
        {
            if (sql[i] == '"')
            {
                if (i + 1 < sql.Length && sql[i + 1] == '"')
                {
                    i += 2;
                    continue;
                }

                return i + 1;
            }

            i++;
        }

        return -1;
    }

    private static bool HasEscapeStringPrefix(string sql, int quoteIndex)
    {
        int prefixIndex = quoteIndex - 1;
        if (prefixIndex < 0 || sql[prefixIndex] is not ('e' or 'E'))
        {
            return false;
        }

        return prefixIndex == 0 || !IsIdentifierPart(sql[prefixIndex - 1]);
    }

    private static bool TryGetDollarQuoteDelimiter(
        string sql,
        int start,
        out string delimiter)
    {
        delimiter = string.Empty;
        int end = sql.IndexOf((char)36, start + 1);
        if (end < 0)
        {
            return false;
        }

        ReadOnlySpan<char> tag = sql.AsSpan(start + 1, end - start - 1);
        if (tag.Length > 0)
        {
            if (!IsDollarTagStart(tag[0]))
            {
                return false;
            }

            for (int i = 1; i < tag.Length; i++)
            {
                if (!IsIdentifierPart(tag[i]))
                {
                    return false;
                }
            }
        }

        delimiter = sql[start..(end + 1)];
        return true;
    }

    private static bool IsDollarTagStart(char value) =>
        value == '_' || char.IsLetter(value);

    private static bool IsIdentifierPart(char value) =>
        value == '_' || value == (char)36 || char.IsLetterOrDigit(value);

    private static void ThrowUnsupported()
    {
        throw new SavException(
            SavErrorCode.UnsupportedConstruct,
            "unsupported_construct: agent SQL rejected by oracle boundary.");
    }
}
