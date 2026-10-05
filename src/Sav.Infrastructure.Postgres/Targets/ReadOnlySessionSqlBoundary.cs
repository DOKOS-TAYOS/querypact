using PgSqlParser;
using Sav.Domain.Errors;

namespace Sav.Infrastructure.Postgres.Targets;

/// <summary>
/// Restricts SQL executed by a retained read-only transaction to query forms.
/// </summary>
internal static class ReadOnlySessionSqlBoundary
{
    private static readonly HashSet<string> AllowedStatementKinds =
        new(StringComparer.Ordinal)
        {
            "SelectStmt",
            "ExplainStmt",
            "VariableShowStmt",
        };

    public static void EnsureAllowed(string sql)
    {
        try
        {
            var parse = Parser.Parse(sql);
            if (parse.Error is not null || parse.Value is null || parse.Value.Stmts.Count != 1)
            {
                ThrowUnsupported();
            }

            ParseResult result = parse.Value!;
            string statementKind = result.Stmts[0].Stmt.NodeCase.ToString();
            if (!AllowedStatementKinds.Contains(statementKind))
            {
                ThrowUnsupported();
            }
        }
        catch (SavException)
        {
            throw;
        }
        catch (Exception)
        {
            ThrowUnsupported();
        }
    }

    private static void ThrowUnsupported()
    {
        throw new SavException(
            SavErrorCode.UnsupportedConstruct,
            "unsupported_construct: read-only session accepts one read-only statement.");
    }
}
