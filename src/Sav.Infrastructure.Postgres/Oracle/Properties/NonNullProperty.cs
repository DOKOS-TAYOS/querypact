using Sav.Application.Abstractions;
using Sav.Domain.Decisions;
using Sav.Domain.Errors;
using Sav.Domain.Properties;

namespace Sav.Infrastructure.Postgres.Oracle.Properties;

/// <summary>
/// <c>non_null</c>: Pass when null-count <c>v = 0</c>. Fail <c>null_found</c> does not egress exact <c>v</c>.
/// </summary>
public static class NonNullProperty
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
            return new PropertyResult("non_null", PropertyStatus.Fail, SavErrorCode.QueryFailed);
        }
        catch (SavException)
        {
            return new PropertyResult("non_null", PropertyStatus.Error, SavErrorCode.QueryFailed);
        }
        catch (Exception)
        {
            return new PropertyResult("non_null", PropertyStatus.Error, SavErrorCode.QueryFailed);
        }
    }

    internal static PropertyResult MapRows(IReadOnlyList<OracleScalarRow> rows)
    {
        ArgumentNullException.ThrowIfNull(rows);
        if (rows.Count != 1 || rows[0].LongV is not long nullCount)
        {
            return new PropertyResult("non_null", PropertyStatus.Error, SavErrorCode.QueryFailed);
        }

        return nullCount == 0
            ? new PropertyResult("non_null", PropertyStatus.Pass, null)
            : new PropertyResult("non_null", PropertyStatus.Fail, SavErrorCode.NullFound);
    }
}
