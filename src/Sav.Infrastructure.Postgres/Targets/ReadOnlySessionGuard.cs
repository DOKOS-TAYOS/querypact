using Npgsql;
using Sav.Application.Abstractions;
using Sav.Domain.Errors;
using Sav.Domain.Policies;

namespace Sav.Infrastructure.Postgres.Targets;

/// <summary>
/// Enforces read-only session proof: the alias must already open read-only transactions, then pass the DML canary on public.sav_ro_probe.
/// </summary>
public sealed class ReadOnlySessionGuard
{
    public const string CanarySql =
        "INSERT INTO public.sav_ro_probe(probe_key) VALUES ('sav-ro-canary')";

    private readonly IRedactor _redactor;
    private readonly DisclosureProfile _disclosure;
    private readonly UnsafeAliasRegistry _unsafeAliases;
    private readonly Func<NpgsqlConnection, NpgsqlTransaction, CancellationToken, Task<CanaryInsertResult>>?
        _canaryOverride;
    private readonly Func<NpgsqlTransaction, CancellationToken, Task>? _rollbackOverride;
    private readonly bool _applyReadOnlyTransaction;
    private readonly Action<string>? _onAliasPanic;

    public ReadOnlySessionGuard(
        IRedactor redactor,
        DisclosureProfile disclosure,
        UnsafeAliasRegistry unsafeAliases)
        : this(
            redactor,
            disclosure,
            unsafeAliases,
            canaryOverride: null,
            rollbackOverride: null,
            applyReadOnlyTransaction: true,
            onAliasPanic: null)
    {
    }

    internal ReadOnlySessionGuard(
        IRedactor redactor,
        DisclosureProfile disclosure,
        UnsafeAliasRegistry unsafeAliases,
        Func<NpgsqlConnection, NpgsqlTransaction, CancellationToken, Task<CanaryInsertResult>>? canaryOverride,
        Func<NpgsqlTransaction, CancellationToken, Task>? rollbackOverride,
        bool applyReadOnlyTransaction,
        Action<string>? onAliasPanic)
    {
        ArgumentNullException.ThrowIfNull(redactor);
        ArgumentNullException.ThrowIfNull(disclosure);
        ArgumentNullException.ThrowIfNull(unsafeAliases);
        _redactor = redactor;
        _disclosure = disclosure;
        _unsafeAliases = unsafeAliases;
        _canaryOverride = canaryOverride;
        _rollbackOverride = rollbackOverride;
        _applyReadOnlyTransaction = applyReadOnlyTransaction;
        _onAliasPanic = onAliasPanic;
    }

    public async Task EnsureReadOnlyAsync(
        string alias,
        NpgsqlConnection connection,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(alias);
        ArgumentNullException.ThrowIfNull(connection);
        cancellationToken.ThrowIfCancellationRequested();

        if (_unsafeAliases.IsUnsafe(alias))
        {
            throw Create("unsafe_write_suspected", SavErrorCode.UnsafeWriteSuspected);
        }

        await using NpgsqlTransaction transaction =
            await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);

        try
        {
            if (_applyReadOnlyTransaction)
            {
                string show = await ExecuteReadOnlyProofAsync(connection, transaction, cancellationToken)
                    .ConfigureAwait(false);
                if (!string.Equals(show, "on", StringComparison.OrdinalIgnoreCase))
                {
                    throw Create("role_not_read_only", SavErrorCode.RoleNotReadOnly);
                }
            }

            CanaryInsertResult canary = _canaryOverride is not null
                ? await _canaryOverride(connection, transaction, cancellationToken).ConfigureAwait(false)
                : await RunDefaultCanaryAsync(connection, transaction, cancellationToken).ConfigureAwait(false);

            switch (canary)
            {
                case CanaryInsertResult.ReadOnlyRejected:
                    await SafeRollbackAsync(alias, transaction, cancellationToken).ConfigureAwait(false);
                    return;

                case CanaryInsertResult.UndefinedTable:
                    await SafeRollbackAsync(alias, transaction, cancellationToken).ConfigureAwait(false);
                    throw Create("ro_probe_missing", SavErrorCode.RoProbeMissing);

                case CanaryInsertResult.Succeeded:
                    await ConfirmRollbackAfterWriteAsync(alias, connection, transaction, cancellationToken)
                        .ConfigureAwait(false);
                    throw Create("role_not_read_only", SavErrorCode.RoleNotReadOnly);

                default:
                    await SafeRollbackAsync(alias, transaction, cancellationToken).ConfigureAwait(false);
                    throw Create("ro_canary_inconclusive", SavErrorCode.RoCanaryInconclusive);
            }
        }
        catch (SavException)
        {
            throw;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            throw Wrap(ex);
        }
    }

    public async Task BeginReadOnlyTransactionAsync(
        NpgsqlConnection connection,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(connection);
        cancellationToken.ThrowIfCancellationRequested();
        await using NpgsqlCommand begin = new("BEGIN READ ONLY", connection);
        await begin.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    private async Task<CanaryInsertResult> RunDefaultCanaryAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction transaction,
        CancellationToken cancellationToken)
    {
        try
        {
            await ExecuteAsync(connection, transaction, CanarySql, cancellationToken).ConfigureAwait(false);
            return CanaryInsertResult.Succeeded;
        }
        catch (PostgresException pg)
        {
            if (IsReadOnlySqlState(pg.SqlState))
            {
                return CanaryInsertResult.ReadOnlyRejected;
            }

            if (string.Equals(pg.SqlState, "42P01", StringComparison.Ordinal))
            {
                return CanaryInsertResult.UndefinedTable;
            }

            return CanaryInsertResult.Inconclusive;
        }
    }

    private async Task ConfirmRollbackAfterWriteAsync(
        string alias,
        NpgsqlConnection connection,
        NpgsqlTransaction transaction,
        CancellationToken cancellationToken)
    {
        try
        {
            if (_rollbackOverride is not null)
            {
                await _rollbackOverride(transaction, cancellationToken).ConfigureAwait(false);
            }
            else
            {
                await transaction.RollbackAsync(cancellationToken).ConfigureAwait(false);
            }
        }
        catch (Exception)
        {
            Panic(alias);
            throw Create("ro_canary_rollback_unconfirmed", SavErrorCode.RoCanaryRollbackUnconfirmed);
        }

        try
        {
            await using NpgsqlCommand check = new(
                "SELECT COUNT(*)::bigint FROM public.sav_ro_probe WHERE probe_key = 'sav-ro-canary'",
                connection);
            object? countObj = await check.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
            long count = countObj is long l ? l : Convert.ToInt64(countObj, System.Globalization.CultureInfo.InvariantCulture);
            if (count > 0)
            {
                Panic(alias);
                throw Create("ro_canary_rollback_unconfirmed", SavErrorCode.RoCanaryRollbackUnconfirmed);
            }
        }
        catch (SavException)
        {
            throw;
        }
        catch (Exception)
        {
            Panic(alias);
            throw Create("ro_canary_rollback_unconfirmed", SavErrorCode.RoCanaryRollbackUnconfirmed);
        }
    }

    private async Task SafeRollbackAsync(
        string alias,
        NpgsqlTransaction transaction,
        CancellationToken cancellationToken)
    {
        try
        {
            await transaction.RollbackAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (Exception)
        {
            Panic(alias);
            throw Create("ro_canary_rollback_unconfirmed", SavErrorCode.RoCanaryRollbackUnconfirmed);
        }
    }

    private void Panic(string alias)
    {
        _unsafeAliases.MarkUnsafe(alias);
        _onAliasPanic?.Invoke(alias);
    }

    private static async Task ExecuteAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction transaction,
        string sql,
        CancellationToken cancellationToken)
    {
        await using NpgsqlCommand command = new(sql, connection, transaction);
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async Task<string> ExecuteReadOnlyProofAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction transaction,
        CancellationToken cancellationToken)
    {
        await using NpgsqlCommand show = new("SHOW transaction_read_only", connection, transaction);
        object? value = await show.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
        return value?.ToString() ?? string.Empty;
    }

    private static bool IsReadOnlySqlState(string? sqlState)
    {
        // 25006 = read_only_sql_transaction
        return string.Equals(sqlState, "25006", StringComparison.Ordinal);
    }

    private SavException Create(string code, string errorCode)
    {
        string message = _redactor.RedactText($"{code}: session refused.", _disclosure);
        return new SavException(errorCode, message);
    }

    private Exception Wrap(Exception ex)
    {
        string message = _redactor.RedactText(ex.Message, _disclosure);
        return new SavException(SavErrorCode.RoCanaryInconclusive, "ro_canary_inconclusive: " + message);
    }
}

internal enum CanaryInsertResult
{
    ReadOnlyRejected,
    UndefinedTable,
    Succeeded,
    Inconclusive,
}
