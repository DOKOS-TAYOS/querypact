using System.Data;
using System.Globalization;
using Npgsql;
using Sav.Application.Abstractions;
using Sav.Domain.Errors;
using Sav.Domain.Policies;

namespace Sav.Infrastructure.Postgres.Oracle;

/// <summary>
/// Writable ephemeral PostgreSQL session for DML properties (Testcontainers / shadow only).
/// Not used against real-alias targets.
/// </summary>
public sealed class EphemeralSession : IAsyncDisposable
{
    private readonly NpgsqlConnection _connection;
    private readonly IRedactor _redactor;
    private readonly DisclosureProfile _disclosure;
    private bool _disposed;

    internal EphemeralSession(
        NpgsqlConnection connection,
        IRedactor redactor,
        DisclosureProfile disclosure)
    {
        ArgumentNullException.ThrowIfNull(connection);
        ArgumentNullException.ThrowIfNull(redactor);
        ArgumentNullException.ThrowIfNull(disclosure);
        _connection = connection;
        _redactor = redactor;
        _disclosure = disclosure;
    }

    public async Task<long> ExecuteDmlAsync(string sql, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sql);
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();

        try
        {
            await using NpgsqlCommand command = new(sql, _connection);
            int affected = await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
            return affected;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            string message = _redactor.RedactText(ex.Message, _disclosure);
            throw new SavException(SavErrorCode.QueryFailed, "query_failed: " + message);
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
        ThrowIfDisposed();

        if (allowedColumns.Count == 0)
        {
            throw new SavException(
                SavErrorCode.SessionReaderColumnsRequired,
                "session_reader_columns_required: allowedColumns must not be empty.");
        }

        try
        {
            Dictionary<string, OracleScalarColumn> allow =
                allowedColumns.ToDictionary(c => c.Name, StringComparer.OrdinalIgnoreCase);

            await using NpgsqlCommand command = new(sql, _connection);
            await using NpgsqlDataReader reader =
                await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);

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
            string message = _redactor.RedactText(ex.Message, _disclosure);
            throw new SavException(SavErrorCode.QueryFailed, "query_failed: " + message);
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        if (_connection.State != ConnectionState.Closed)
        {
            await _connection.DisposeAsync().ConfigureAwait(false);
        }
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
    }
}

/// <summary>
/// Opens writable ephemeral sessions from an operator-supplied connection string (Testcontainers).
/// </summary>
public sealed class EphemeralSessionFactory
{
    private readonly IRedactor _redactor;
    private readonly DisclosureProfile _disclosure;

    public EphemeralSessionFactory(IRedactor redactor, DisclosureProfile disclosure)
    {
        ArgumentNullException.ThrowIfNull(redactor);
        ArgumentNullException.ThrowIfNull(disclosure);
        _redactor = redactor;
        _disclosure = disclosure;
    }

    public async Task<EphemeralSession> OpenAsync(string connectionString, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(connectionString);
        cancellationToken.ThrowIfCancellationRequested();

        NpgsqlConnection connection = new(connectionString);
        try
        {
            await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
            await PgSessionTimeouts
                .ApplyAsync(
                    connection,
                    statementTimeoutMilliseconds: 3000,
                    lockTimeoutMilliseconds: 1000,
                    cancellationToken)
                .ConfigureAwait(false);
            return new EphemeralSession(connection, _redactor, _disclosure);
        }
        catch
        {
            await connection.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

}
