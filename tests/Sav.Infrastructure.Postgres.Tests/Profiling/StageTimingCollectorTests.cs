namespace Sav.Infrastructure.Postgres.Tests.Profiling;

public sealed class StageTimingCollectorTests
{
    [Fact]
    public async Task Measure_async_accumulates_call_count_and_elapsed_time()
    {
        StageTimingCollector collector = new();

        await collector.MeasureAsync("plan", static () => Task.FromResult(1));
        await collector.MeasureAsync("plan", static () => Task.FromResult(2));

        StageTimingSnapshot snapshot = collector.GetSnapshot("plan");

        Assert.Equal(2, snapshot.CallCount);
        Assert.True(snapshot.ElapsedTicks >= 0);
    }

    [Fact]
    public async Task Measure_async_records_timing_when_operation_throws()
    {
        StageTimingCollector collector = new();

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            collector.MeasureAsync<int>("plan", static () => throw new InvalidOperationException()));

        StageTimingSnapshot snapshot = collector.GetSnapshot("plan");

        Assert.Equal(1, snapshot.CallCount);
        Assert.True(snapshot.ElapsedTicks >= 0);
    }

    [Fact]
    public async Task Measure_async_records_timing_when_operation_is_cancelled()
    {
        using CancellationTokenSource cancellation = new();
        cancellation.Cancel();
        StageTimingCollector collector = new();

        await Assert.ThrowsAsync<TaskCanceledException>(() =>
            collector.MeasureAsync("plan", () => Task.FromCanceled<int>(cancellation.Token)));

        StageTimingSnapshot snapshot = collector.GetSnapshot("plan");

        Assert.Equal(1, snapshot.CallCount);
        Assert.True(snapshot.ElapsedTicks >= 0);
    }

    [Fact]
    public void Get_snapshot_returns_zero_for_an_unseen_stage()
    {
        StageTimingCollector collector = new();

        StageTimingSnapshot snapshot = collector.GetSnapshot("missing");

        Assert.Equal(0, snapshot.CallCount);
        Assert.Equal(0, snapshot.ElapsedTicks);
    }

    [Fact]
    public async Task Reset_clears_all_snapshots()
    {
        StageTimingCollector collector = new();
        await collector.MeasureAsync("plan", static () => Task.FromResult(1));

        collector.Reset();

        StageTimingSnapshot snapshot = collector.GetSnapshot("plan");
        Assert.Equal(0, snapshot.CallCount);
        Assert.Equal(0, snapshot.ElapsedTicks);
    }
}
