using Sav.Application.Abstractions;
using Sav.Domain.Decisions;
using Sav.Domain.Errors;
using Sav.Domain.Properties;

namespace Sav.Infrastructure.Postgres.Oracle.Properties;

/// <summary>
/// <c>empty_result</c>: Pass when the NOT EXISTS wrapper returns <c>v = true</c> (zero rows).
/// </summary>
public static class EmptyResultProperty
{
    public static async Task<PropertyResult> EvaluateAsync(
        IReadOnlySession session,
        string wrappedSql,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(session);
        ArgumentException.ThrowIfNullOrWhiteSpace(wrappedSql);
        cancellationToken.ThrowIfCancellationRequested();

        try
        {
            IReadOnlyList<OracleScalarRow> rows = await session
                .ExecuteReaderAsync(wrappedSql, [OracleSqlTemplate.BoolVColumn], cancellationToken)
                .ConfigureAwait(false);

            return MapRows(rows);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (SavException ex) when (ex.Code == SavErrorCode.QueryFailed)
        {
            return new PropertyResult("empty_result", PropertyStatus.Fail, SavErrorCode.QueryFailed);
        }
        catch (SavException)
        {
            return new PropertyResult("empty_result", PropertyStatus.Error, SavErrorCode.QueryFailed);
        }
        catch (Exception)
        {
            return new PropertyResult("empty_result", PropertyStatus.Error, SavErrorCode.QueryFailed);
        }
    }

    internal static PropertyResult MapRows(IReadOnlyList<OracleScalarRow> rows)
    {
        ArgumentNullException.ThrowIfNull(rows);
        if (rows.Count != 1 || rows[0].BoolV is not bool isEmpty)
        {
            return new PropertyResult("empty_result", PropertyStatus.Error, SavErrorCode.QueryFailed);
        }

        return isEmpty
            ? new PropertyResult("empty_result", PropertyStatus.Pass, null)
            : new PropertyResult("empty_result", PropertyStatus.Fail, SavErrorCode.EmptyExpectedRows);
    }
}
