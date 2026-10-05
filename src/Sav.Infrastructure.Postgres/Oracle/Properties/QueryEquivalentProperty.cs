using Sav.Application.Abstractions;
using Sav.Domain.Decisions;
using Sav.Domain.Errors;
using Sav.Domain.Properties;
using Sav.Infrastructure.Postgres.Targets;

namespace Sav.Infrastructure.Postgres.Oracle.Properties;

/// <summary>
/// <c>query_equivalent</c>: evaluate EXCEPT ALL in both directions inside one PostgreSQL statement
/// so both comparisons share one statement snapshot. Pass when the combined difference marker is 0.
/// </summary>
public static class QueryEquivalentProperty
{
    public static async Task<PropertyResult> EvaluateAsync(
        Func<string, CancellationToken, Task<IReadOnlyList<OracleScalarRow>>> executeCountAsync,
        string leftSql,
        string rightSql,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(executeCountAsync);
        ArgumentException.ThrowIfNullOrWhiteSpace(leftSql);
        ArgumentException.ThrowIfNullOrWhiteSpace(rightSql);
        cancellationToken.ThrowIfCancellationRequested();

        try
        {
            string wrapped = BuildWrappedQuery(leftSql, rightSql);
            long difference = await ReadCountAsync(executeCountAsync, wrapped, cancellationToken)
                .ConfigureAwait(false);

            return MapCount(difference);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (SavException ex) when (ex.Code == SavErrorCode.QueryFailed)
        {
            return new PropertyResult("query_equivalent", PropertyStatus.Fail, SavErrorCode.QueryFailed);
        }
        catch (Exception)
        {
            return new PropertyResult("query_equivalent", PropertyStatus.Error, SavErrorCode.QueryFailed);
        }
    }

    internal static async Task<PropertyResult> EvaluateBatchAsync(
        IOracleBatchReadSession session,
        string leftSql,
        string rightSql,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(session);
        ArgumentException.ThrowIfNullOrWhiteSpace(leftSql);
        ArgumentException.ThrowIfNullOrWhiteSpace(rightSql);
        cancellationToken.ThrowIfCancellationRequested();

        try
        {
            string wrapped = BuildWrappedQuery(leftSql, rightSql);
            IReadOnlyList<IReadOnlyList<OracleScalarRow>> results = await session
                .ExecuteBatchAsync(
                    [new OracleBatchReadCommand(wrapped, [OracleSqlTemplate.LongVColumn])],
                    cancellationToken)
                .ConfigureAwait(false);

            if (results.Count != 1)
            {
                throw new SavException(SavErrorCode.QueryFailed, "query_failed: equivalence result shape invalid.");
            }

            return MapCount(ReadCount(results[0]));
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (SavException ex) when (ex.Code == SavErrorCode.QueryFailed)
        {
            return new PropertyResult("query_equivalent", PropertyStatus.Fail, SavErrorCode.QueryFailed);
        }
        catch (Exception)
        {
            return new PropertyResult("query_equivalent", PropertyStatus.Error, SavErrorCode.QueryFailed);
        }
    }

    private static string BuildWrappedQuery(string leftSql, string rightSql)
    {
        (string leftWrap, string rightWrap) = BuildDirectionalQueries(leftSql, rightSql);
        return "SELECT CASE WHEN ((" + leftWrap + ") = 0 AND (" + rightWrap
            + ") = 0) THEN 0 ELSE 1 END::bigint AS v";
    }

    private static (string Left, string Right) BuildDirectionalQueries(string leftSql, string rightSql) =>
        (
            OracleSqlTemplate.WrapExceptAll(
                OracleSqlTemplateKind.QueryEquivalentExceptLeft,
                leftSql,
                rightSql),
            OracleSqlTemplate.WrapExceptAll(
                OracleSqlTemplateKind.QueryEquivalentExceptRight,
                leftSql,
                rightSql));

    private static PropertyResult MapCount(long difference) =>
        difference == 0
            ? new PropertyResult("query_equivalent", PropertyStatus.Pass, null)
            : new PropertyResult("query_equivalent", PropertyStatus.Fail, SavErrorCode.NotEquivalent);

    private static async Task<long> ReadCountAsync(
        Func<string, CancellationToken, Task<IReadOnlyList<OracleScalarRow>>> executeCountAsync,
        string sql,
        CancellationToken cancellationToken)
    {
        IReadOnlyList<OracleScalarRow> rows =
            await executeCountAsync(sql, cancellationToken).ConfigureAwait(false);

        if (rows.Count != 1)
        {
            throw new SavException(SavErrorCode.QueryFailed, "query_failed: equivalence count shape invalid.");
        }

        return ReadCount(rows);
    }

    private static long ReadCount(IReadOnlyList<OracleScalarRow> rows)
    {
        if (rows.Count != 1
            || rows[0].LongV is not long count
            || rows[0].BoolV is not null
            || rows[0].StringV is not null)
        {
            throw new SavException(SavErrorCode.QueryFailed, "query_failed: equivalence count shape invalid.");
        }

        return count;
    }
}
