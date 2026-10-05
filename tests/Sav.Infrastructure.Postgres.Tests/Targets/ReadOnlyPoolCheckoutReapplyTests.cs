using Npgsql;
using Sav.Application.Abstractions;
using Sav.Domain.Errors;
using Sav.Domain.Targets;
using Sav.Infrastructure.Postgres.Targets;
using Sav.Infrastructure.Postgres.Tests.Fixtures;

namespace Sav.Infrastructure.Postgres.Tests.Targets;

[Collection(nameof(PostgresRoCollection))]
public sealed class ReadOnlyPoolCheckoutReapplyTests
{
    private readonly PostgresRoFixture _fixture;

    public ReadOnlyPoolCheckoutReapplyTests(PostgresRoFixture fixture)
    {
        _fixture = fixture;
    }

    [Fact]
    public async Task Successful_commands_share_the_factory_transaction()
    {
        await using ReadOnlySessionFactory factory = _fixture.CreateFactory();
        TargetAlias alias = _fixture.Resolve(PostgresRoFixture.RoAlias);
        await using IReadOnlySession session =
            await factory.OpenReadOnlySessionAsync(alias, CancellationToken.None);

        IReadOnlyList<OracleScalarRow> first = await session.ExecuteReaderAsync(
            "SELECT txid_current() AS v",
            [new OracleScalarColumn("v", OracleScalarKind.LongV)],
            CancellationToken.None);

        IReadOnlyList<OracleScalarRow> second = await session.ExecuteReaderAsync(
            "SELECT txid_current() AS v",
            [new OracleScalarColumn("v", OracleScalarKind.LongV)],
            CancellationToken.None);

        Assert.Equal(first[0].LongV, second[0].LongV);
    }

    [Fact]
    public async Task Failed_command_resets_the_transaction_before_the_next_command()
    {
        await using ReadOnlySessionFactory factory = _fixture.CreateFactory();
        TargetAlias alias = _fixture.Resolve(PostgresRoFixture.RoAlias);
        await using IReadOnlySession session =
            await factory.OpenReadOnlySessionAsync(alias, CancellationToken.None);

        await Assert.ThrowsAsync<SavException>(
            () => session.ExecuteAsync("SELECT 1 / 0", CancellationToken.None));

        IReadOnlyList<OracleScalarRow> rows = await session.ExecuteReaderAsync(
            "SELECT 1 AS v",
            [new OracleScalarColumn("v", OracleScalarKind.LongV)],
            CancellationToken.None);
        Assert.Equal(1, rows[0].LongV);

        await Assert.ThrowsAsync<Sav.Domain.Errors.SavException>(
            () => session.ExecuteAsync(
                "INSERT INTO public.sav_ro_probe(probe_key) VALUES ('should-fail')",
                CancellationToken.None));
    }

    [Fact]
    public async Task Cancelled_command_resets_the_transaction_before_the_next_command()
    {
        await using ReadOnlySessionFactory factory = _fixture.CreateFactory();
        TargetAlias alias = _fixture.Resolve(PostgresRoFixture.RoAlias);
        await using IReadOnlySession session =
            await factory.OpenReadOnlySessionAsync(alias, CancellationToken.None);
        using CancellationTokenSource cancellation = new();

        Task running = session.ExecuteAsync("SELECT pg_sleep(5)", cancellation.Token);
        await WaitForActiveQueryAsync("SELECT pg_sleep(5)");
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => running);

        IReadOnlyList<OracleScalarRow> rows = await session.ExecuteReaderAsync(
            "SELECT 1 AS v",
            [new OracleScalarColumn("v", OracleScalarKind.LongV)],
            CancellationToken.None);
        Assert.Equal(1, rows[0].LongV);

        await Assert.ThrowsAsync<Sav.Domain.Errors.SavException>(
            () => session.ExecuteAsync(
                "INSERT INTO public.sav_ro_probe(probe_key) VALUES ('should-fail')",
                CancellationToken.None));
    }

    [Fact]
    public async Task Dispose_after_backend_loss_is_best_effort_and_factory_can_reopen()
    {
        await using ReadOnlySessionFactory factory = _fixture.CreateFactory();
        TargetAlias alias = _fixture.Resolve(PostgresRoFixture.RoAlias);
        IReadOnlySession session =
            await factory.OpenReadOnlySessionAsync(alias, CancellationToken.None);

        IReadOnlyList<OracleScalarRow> pidRows = await session.ExecuteReaderAsync(
            "SELECT pg_backend_pid()::bigint AS v",
            [new OracleScalarColumn("v", OracleScalarKind.LongV)],
            CancellationToken.None);
        long backendPid = Assert.IsType<long>(pidRows[0].LongV);

        await TerminateBackendAsync(backendPid);

        await session.DisposeAsync();
        await session.DisposeAsync();

        await using IReadOnlySession reopened =
            await factory.OpenReadOnlySessionAsync(alias, CancellationToken.None);
        IReadOnlyList<OracleScalarRow> rows = await reopened.ExecuteReaderAsync(
            "SELECT 1 AS v",
            [new OracleScalarColumn("v", OracleScalarKind.LongV)],
            CancellationToken.None);

        Assert.Equal(1, rows[0].LongV);
    }

    [Fact]
    public async Task Transaction_control_and_multiple_statements_are_rejected_on_read_only_alias()
    {
        await using ReadOnlySessionFactory factory = _fixture.CreateFactory();
        TargetAlias alias = _fixture.Resolve(PostgresRoFixture.RoAlias);
        await using IReadOnlySession session =
            await factory.OpenReadOnlySessionAsync(alias, CancellationToken.None);
        string marker = Guid.NewGuid().ToString("N");

        SavException executeError = await Assert.ThrowsAsync<SavException>(
            () => session.ExecuteAsync("ROLLBACK", CancellationToken.None));
        Assert.Equal(SavErrorCode.UnsupportedConstruct, executeError.Code);

        SavException readerError = await Assert.ThrowsAsync<SavException>(
            () => session.ExecuteReaderAsync(
                "SELECT 1 AS v; ROLLBACK",
                [new OracleScalarColumn("v", OracleScalarKind.LongV)],
                CancellationToken.None));
        Assert.Equal(SavErrorCode.UnsupportedConstruct, readerError.Code);

        await Assert.ThrowsAsync<SavException>(
            () => session.ExecuteAsync(
                $"INSERT INTO public.side_effect_sink(v) VALUES ('{marker}')",
                CancellationToken.None));

        Assert.Equal(0L, await CountSideEffectRowsAsync(marker));
    }

    private async Task TerminateBackendAsync(long backendPid)
    {
        await using NpgsqlConnection admin = new(_fixture.AdminConnectionString);
        await admin.OpenAsync();
        await using NpgsqlCommand command = new(
            "SELECT pg_terminate_backend(@pid)",
            admin);
        command.Parameters.AddWithValue("pid", checked((int)backendPid));
        object? terminated = await command.ExecuteScalarAsync();
        Assert.Equal(true, terminated);
    }

    private async Task WaitForActiveQueryAsync(string query)
    {
        using CancellationTokenSource timeout = new(TimeSpan.FromSeconds(3));
        while (true)
        {
            timeout.Token.ThrowIfCancellationRequested();
            await using NpgsqlConnection admin = new(_fixture.AdminConnectionString);
            await admin.OpenAsync(timeout.Token);
            await using NpgsqlCommand command = new(
                """
                SELECT EXISTS (
                    SELECT 1
                    FROM pg_stat_activity
                    WHERE state = 'active' AND query = @query)
                """,
                admin);
            command.Parameters.AddWithValue("query", query);
            bool active = (bool)(await command.ExecuteScalarAsync(timeout.Token)
                ?? throw new InvalidOperationException("Expected an activity result."));
            if (active)
            {
                return;
            }

            await Task.Delay(TimeSpan.FromMilliseconds(25), timeout.Token);
        }
    }

    private async Task<long> CountSideEffectRowsAsync(string marker)
    {
        await using NpgsqlConnection admin = new(_fixture.AdminConnectionString);
        await admin.OpenAsync();
        await using NpgsqlCommand command = new(
            "SELECT COUNT(*) FROM public.side_effect_sink WHERE v = @marker",
            admin);
        command.Parameters.AddWithValue("marker", marker);
        object? result = await command.ExecuteScalarAsync();
        return Convert.ToInt64(result, System.Globalization.CultureInfo.InvariantCulture);
    }
}
