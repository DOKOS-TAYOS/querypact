using System.Collections.Concurrent;
using Npgsql;
using Sav.Application.Abstractions;
using Sav.Domain.Errors;
using Sav.Domain.Targets;

namespace Sav.Infrastructure.Postgres.Targets;

public sealed class ReadOnlySessionFactory : IReadOnlySessionFactory, IAsyncDisposable
{
    private readonly AliasConnectionFactory _connectionFactory;
    private readonly ReadOnlySessionGuard _guard;
    private readonly IRedactor _redactor;
    private readonly ReadOnlySessionOptions _options;
    private readonly UnsafeAliasRegistry _unsafeAliases;
    private readonly ConcurrentDictionary<string, NpgsqlDataSource> _dataSources = new(StringComparer.OrdinalIgnoreCase);
    private bool _disposed;

    public ReadOnlySessionFactory(
        AliasConnectionFactory connectionFactory,
        ReadOnlySessionGuard guard,
        IRedactor redactor,
        ReadOnlySessionOptions options,
        UnsafeAliasRegistry unsafeAliases)
    {
        ArgumentNullException.ThrowIfNull(connectionFactory);
        ArgumentNullException.ThrowIfNull(guard);
        ArgumentNullException.ThrowIfNull(redactor);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(unsafeAliases);
        _connectionFactory = connectionFactory;
        _guard = guard;
        _redactor = redactor;
        _options = options;
        _unsafeAliases = unsafeAliases;
    }

    public async Task<IReadOnlySession> OpenReadOnlySessionAsync(
        TargetAlias target,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(target);
        cancellationToken.ThrowIfCancellationRequested();
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (_unsafeAliases.IsUnsafe(target.Alias))
        {
            throw new SavException(
                SavErrorCode.UnsafeWriteSuspected,
                "unsafe_write_suspected: alias is marked unsafe.");
        }

        NpgsqlConnection? connection = null;
        try
        {
            NpgsqlDataSource dataSource = GetOrCreateDataSource(target);
            connection = await dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
            await PgSessionTimeouts
                .ApplyAsync(
                    connection,
                    ToMilliseconds(_options.StatementTimeout),
                    ToMilliseconds(_options.LockTimeout),
                    cancellationToken)
                .ConfigureAwait(false);
            await _guard.EnsureReadOnlyAsync(target.Alias, connection, cancellationToken).ConfigureAwait(false);
            await _guard.BeginReadOnlyTransactionAsync(connection, cancellationToken).ConfigureAwait(false);
            ReadOnlySession session = new(connection, _guard, _redactor, _options.Disclosure);
            connection = null;
            return session;
        }
        catch (OperationCanceledException)
        {
            if (connection is not null)
            {
                await connection.DisposeAsync().ConfigureAwait(false);
            }

            throw;
        }
        catch (SavException)
        {
            if (connection is not null)
            {
                await connection.DisposeAsync().ConfigureAwait(false);
            }

            throw;
        }
        catch (Exception ex)
        {
            if (connection is not null)
            {
                await connection.DisposeAsync().ConfigureAwait(false);
            }

            string message = _redactor.RedactText(ex.Message, _options.Disclosure);
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
        foreach (KeyValuePair<string, NpgsqlDataSource> pair in _dataSources)
        {
            await pair.Value.DisposeAsync().ConfigureAwait(false);
        }

        _dataSources.Clear();
    }

    internal void DisposePoolWithoutReuse(string alias)
    {
        if (_dataSources.TryRemove(alias, out NpgsqlDataSource? dataSource))
        {
            dataSource.Dispose();
        }

        _unsafeAliases.MarkUnsafe(alias);
    }

    private NpgsqlDataSource GetOrCreateDataSource(TargetAlias target)
    {
        return _dataSources.GetOrAdd(target.Alias, _ =>
        {
            string dsn = _connectionFactory.RequireDsn(target);
            NpgsqlDataSourceBuilder builder = new(dsn);
            return builder.Build();
        });
    }

    private static int ToMilliseconds(TimeSpan value)
    {
        if (value <= TimeSpan.Zero)
        {
            return 1;
        }

        double ms = value.TotalMilliseconds;
        if (ms > int.MaxValue)
        {
            return int.MaxValue;
        }

        return Math.Max(1, (int)ms);
    }
}
