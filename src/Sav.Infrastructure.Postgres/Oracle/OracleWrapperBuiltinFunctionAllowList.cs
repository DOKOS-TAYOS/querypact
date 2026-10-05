using System.Collections.Frozen;

namespace Sav.Infrastructure.Postgres.Oracle;

/// <summary>
/// Frozen empty set. Template scaffolding (EXISTS / COUNT / EXCEPT ALL) is SQL syntax emitted by QueryPact,
/// not an agent-callable builtin whitelist. No pg_*, dblink, or lo_* functions are builtins.
/// </summary>
public static class OracleWrapperBuiltinFunctionAllowList
{
    public static IReadOnlySet<string> Allowed { get; } =
        FrozenSet.ToFrozenSet(Array.Empty<string>(), StringComparer.OrdinalIgnoreCase);

    public static bool IsAllowed(string functionName)
    {
        if (string.IsNullOrWhiteSpace(functionName))
        {
            return false;
        }

        return Allowed.Contains(functionName);
    }
}
