using System.Diagnostics;

namespace Sav.Infrastructure.Postgres.Tests.Profiling;

internal sealed record StageTimingSnapshot(int CallCount, long ElapsedTicks);

internal sealed class StageTimingCollector
{
    private readonly Lock _sync = new();
    private readonly Dictionary<string, StageTimingSnapshot> _snapshots = new(StringComparer.Ordinal);

    public async Task<T> MeasureAsync<T>(string stage, Func<Task<T>> operation)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(stage);
        ArgumentNullException.ThrowIfNull(operation);

        long startedAt = Stopwatch.GetTimestamp();
        try
        {
            return await operation();
        }
        finally
        {
            long elapsedTicks = Stopwatch.GetTimestamp() - startedAt;
            lock (_sync)
            {
                StageTimingSnapshot current = GetSnapshotUnsafe(stage);
                _snapshots[stage] = new StageTimingSnapshot(
                    current.CallCount + 1,
                    current.ElapsedTicks + elapsedTicks);
            }
        }
    }

    public StageTimingSnapshot GetSnapshot(string stage)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(stage);

        lock (_sync)
        {
            return GetSnapshotUnsafe(stage);
        }
    }

    public void Reset()
    {
        lock (_sync)
        {
            _snapshots.Clear();
        }
    }

    private StageTimingSnapshot GetSnapshotUnsafe(string stage) =>
        _snapshots.GetValueOrDefault(stage, new StageTimingSnapshot(0, 0));
}
