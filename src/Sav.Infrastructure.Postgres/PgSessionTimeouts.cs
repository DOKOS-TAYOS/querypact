using System.Globalization;
using Npgsql;

namespace Sav.Infrastructure.Postgres;

internal static class PgSessionTimeouts
{
    public static async Task ApplyAsync(
        NpgsqlConnection connection,
        int statementTimeoutMilliseconds,
        int lockTimeoutMilliseconds,
        CancellationToken cancellationToken)
    {
        await using NpgsqlBatch batch = new(connection);
        batch.BatchCommands.Add(new NpgsqlBatchCommand(
            $"SET statement_timeout = {statementTimeoutMilliseconds.ToString(CultureInfo.InvariantCulture)}"));
        batch.BatchCommands.Add(new NpgsqlBatchCommand(
            $"SET lock_timeout = {lockTimeoutMilliseconds.ToString(CultureInfo.InvariantCulture)}"));
        await batch.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }
}
