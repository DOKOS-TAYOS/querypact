using Sav.Application.Abstractions;
using Sav.Domain.Decisions;
using Sav.Domain.Errors;
using Sav.Domain.Properties;

namespace Sav.Infrastructure.Postgres.Oracle.Properties;

/// <summary>
/// <c>unique</c>: Pass when all non-null values are distinct. Nullability is checked separately by <c>non_null</c>.
/// </summary>
public static class UniqueProperty
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
                .ExecuteReaderAsync(wrappedSql, [OracleSqlTemplate.LongVColumn], cancellationToken)
                .ConfigureAwait(false);

            return MapRows(rows);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (SavException ex) when (ex.Code == SavErrorCode.QueryFailed)
        {
            return new PropertyResult("unique", PropertyStatus.Fail, SavErrorCode.QueryFailed);
        }
        catch (SavException)
        {
            return new PropertyResult("unique", PropertyStatus.Error, SavErrorCode.QueryFailed);
        }
        catch (Exception)
        {
            return new PropertyResult("unique", PropertyStatus.Error, SavErrorCode.QueryFailed);
        }
    }

    internal static PropertyResult MapRows(IReadOnlyList<OracleScalarRow> rows)
    {
        ArgumentNullException.ThrowIfNull(rows);
        if (rows.Count == 0)
        {
            return new PropertyResult("unique", PropertyStatus.Pass, null);
        }

        return rows.Count == 1
            ? new PropertyResult("unique", PropertyStatus.Fail, SavErrorCode.UniqueViolation)
            : new PropertyResult("unique", PropertyStatus.Error, SavErrorCode.QueryFailed);
    }
}
