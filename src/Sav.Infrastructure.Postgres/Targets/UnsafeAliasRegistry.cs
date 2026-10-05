using System.Collections.Concurrent;

namespace Sav.Infrastructure.Postgres.Targets;

/// <summary>
/// Tracks aliases marked unsafe after unconfirmed canary rollback (fail-closed; no pool reuse).
/// </summary>
public sealed class UnsafeAliasRegistry
{
    private readonly ConcurrentDictionary<string, byte> _unsafe =
        new(StringComparer.OrdinalIgnoreCase);

    public void MarkUnsafe(string alias)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(alias);
        _unsafe[alias] = 0;
    }

    public bool IsUnsafe(string alias)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(alias);
        return _unsafe.ContainsKey(alias);
    }
}
