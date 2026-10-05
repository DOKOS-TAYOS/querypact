using System.Data;
using System.Globalization;
using Npgsql;
using Sav.Application.Abstractions;
using Sav.Domain.Errors;
using Sav.Domain.Policies;

namespace Sav.Infrastructure.Postgres.Targets;

public sealed class ReadOnlySession : IReadOnlySession, IOracleBatchReadSession
{
    private readonly NpgsqlConnection _connection;
    private readonly ReadOnlySessionGuard _guard;
    private readonly IRedactor _redactor;
    private readonly DisclosureProfile _disclosure;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private bool _requiresTransactionReset;
    private bool _disposed;

    internal ReadOnlySession(
        NpgsqlConnection connection,
        ReadOnlySessionGuard guard,
        IRedactor redactor,
        DisclosureProfile disclosure)
    {
        ArgumentNullException.ThrowIfNull(connection);
        ArgumentNullException.ThrowIfNull(guard);
        ArgumentNullException.ThrowIfNull(redactor);
        ArgumentNullException.ThrowIfNull(disclosure);
        _connection = connection;
        _guard = guard;
        _redactor = redactor;
        _disclosure = disclosure;
    }

    public async Task ExecuteAsync(string sql, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sql);
        cancellationToken.ThrowIfCancellationRequested();
        ReadOnlySessionSqlBoundary.EnsureAllowed(sql);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            await EnsureReadOnlyCheckoutAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                await using NpgsqlCommand command = new(sql, _connection);
                await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (NpgsqlException)
            {
                _requiresTransactionReset = true;
                throw;
            }
            catch (OperationCanceledException)
            {
                _requiresTransactionReset = true;
                throw;
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (SavException)
        {
            throw;
        }
        catch (Exception ex)
        {
            throw Wrap(ex);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<IReadOnlyList<OracleScalarRow>> ExecuteReaderAsync(
        string sql,
        IReadOnlyList<OracleScalarColumn> allowedColumns,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sql);
        ArgumentNullException.ThrowIfNull(allowedColumns);
        cancellationToken.ThrowIfCancellationRequested();
        ReadOnlySessionSqlBoundary.EnsureAllowed(sql);

        if (allowedColumns.Count == 0)
        {
            throw new SavException(
                SavErrorCode.SessionReaderColumnsRequired,
                "session_reader_columns_required: allowedColumns must not be empty.");
        }

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            await EnsureReadOnlyCheckoutAsync(cancellationToken).ConfigureAwait(false);

            try
            {
                await using NpgsqlCommand command = new(sql, _connection);
                await using NpgsqlDataReader reader =
                    await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
                return await ReadRowsAsync(reader, allowedColumns, cancellationToken).ConfigureAwait(false);
            }
            catch (NpgsqlException)
            {
                _requiresTransactionReset = true;
                throw;
            }
            catch (OperationCanceledException)
            {
                _requiresTransactionReset = true;
                throw;
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (SavException)
        {
            throw;
        }
        catch (Exception ex)
        {
            throw Wrap(ex);
        }
        finally
        {
            _gate.Release();
        }
    }

    async Task<IReadOnlyList<IReadOnlyList<OracleScalarRow>>> IOracleBatchReadSession.ExecuteBatchAsync(
        IReadOnlyList<OracleBatchReadCommand> commands,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(commands);
        cancellationToken.ThrowIfCancellationRequested();
        if (commands.Count == 0)
        {
            throw new ArgumentException("At least one batch command is required.", nameof(commands));
        }

        foreach (OracleBatchReadCommand command in commands)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(command.Sql);
            ArgumentNullException.ThrowIfNull(command.AllowedColumns);
            ReadOnlySessionSqlBoundary.EnsureAllowed(command.Sql);
            if (command.AllowedColumns.Count == 0)
            {
                throw new SavException(
                    SavErrorCode.SessionReaderColumnsRequired,
                    "session_reader_columns_required: allowedColumns must not be empty.");
            }
        }

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            await EnsureReadOnlyCheckoutAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                await using NpgsqlBatch batch = new(_connection);
                foreach (OracleBatchReadCommand command in commands)
                {
                    batch.BatchCommands.Add(new NpgsqlBatchCommand(command.Sql));
                }

                await using NpgsqlDataReader reader = await batch
                    .ExecuteReaderAsync(cancellationToken)
                    .ConfigureAwait(false);
                List<IReadOnlyList<OracleScalarRow>> results = new(commands.Count);
                for (int commandIndex = 0; commandIndex < commands.Count; commandIndex++)
                {
                    results.Add(await ReadRowsAsync(
                        reader,
                        commands[commandIndex].AllowedColumns,
                        cancellationToken).ConfigureAwait(false));
                    if (commandIndex + 1 < commands.Count)
                    {
                        if (!await reader.NextResultAsync(cancellationToken).ConfigureAwait(false))
                        {
                            throw new SavException(SavErrorCode.QueryFailed, "query_failed: batch result set missing.");
                        }
                    }
                }

                return results;
            }
            catch (NpgsqlException)
            {
                _requiresTransactionReset = true;
                throw;
            }
            catch (OperationCanceledException)
            {
                _requiresTransactionReset = true;
                throw;
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (SavException)
        {
            throw;
        }
        catch (Exception ex)
        {
            throw Wrap(ex);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        try
        {
            if (_connection.State != ConnectionState.Closed)
            {
                try
                {
                    await using NpgsqlCommand rollback = new("ROLLBACK", _connection);
                    await rollback.ExecuteNonQueryAsync(CancellationToken.None).ConfigureAwait(false);
                }
                catch (NpgsqlException)
                {
                    // Best-effort rollback during teardown; connection disposal still follows.
                }
                catch (InvalidOperationException)
                {
                    // Broken/invalid connection state during teardown; connection disposal still follows.
                }
            }
        }
        finally
        {
            try
            {
                await _connection.DisposeAsync().ConfigureAwait(false);
            }
            finally
            {
                _gate.Dispose();
            }
        }
    }

    private async Task EnsureReadOnlyCheckoutAsync(CancellationToken cancellationToken)
    {
        if (!_requiresTransactionReset)
        {
            return;
        }

        try
        {
            await using NpgsqlCommand rollback = new("ROLLBACK", _connection);
            await rollback.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (PostgresException)
        {
            // No transaction in progress.
        }

        await _guard.BeginReadOnlyTransactionAsync(_connection, cancellationToken).ConfigureAwait(false);
        _requiresTransactionReset = false;
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
    }

    private static async Task<IReadOnlyList<OracleScalarRow>> ReadRowsAsync(
        NpgsqlDataReader reader,
        IReadOnlyList<OracleScalarColumn> allowedColumns,
        CancellationToken cancellationToken)
    {
        Dictionary<string, OracleScalarColumn> allow =
            allowedColumns.ToDictionary(c => c.Name, StringComparer.OrdinalIgnoreCase);
        List<OracleScalarRow> rows = [];
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            for (int i = 0; i < reader.FieldCount; i++)
            {
                string columnName = reader.GetName(i);
                if (!allow.ContainsKey(columnName))
                {
                    throw new SavException(
                        SavErrorCode.SessionReaderColumnForbidden,
                        "session_reader_column_forbidden: column is not allowed.");
                }
            }

            bool? boolV = null;
            long? longV = null;
            string? stringV = null;
            foreach (OracleScalarColumn column in allowedColumns)
            {
                int ordinal;
                try
                {
                    ordinal = reader.GetOrdinal(column.Name);
                }
                catch (IndexOutOfRangeException)
                {
                    continue;
                }

                if (reader.IsDBNull(ordinal))
                {
                    continue;
                }

                switch (column.Kind)
                {
                    case OracleScalarKind.BoolV:
                        boolV = reader.GetBoolean(ordinal);
                        break;
                    case OracleScalarKind.LongV:
                        longV = Convert.ToInt64(reader.GetValue(ordinal), CultureInfo.InvariantCulture);
                        break;
                    case OracleScalarKind.StringV:
                        stringV = reader.GetValue(ordinal)?.ToString();
                        break;
                    default:
                        throw new SavException(
                            SavErrorCode.SessionReaderColumnForbidden,
                            "session_reader_column_forbidden: unsupported scalar kind.");
                }
            }

            rows.Add(new OracleScalarRow(boolV, longV, stringV));
        }

        return rows;
    }

    private Exception Wrap(Exception ex)
    {
        string message = _redactor.RedactText(ex.Message, _disclosure);
        return new SavException(SavErrorCode.QueryFailed, "query_failed: " + message);
    }
}
