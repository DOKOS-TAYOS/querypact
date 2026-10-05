using Sav.Application.Abstractions;
using Sav.Domain.Decisions;
using Sav.Domain.Errors;
using Sav.Domain.Properties;

namespace Sav.Infrastructure.Postgres.Oracle.Properties;

/// <summary>
/// <c>no_new_orphans</c>: strict final-state postcondition. Pass only when the orphan count is 0;
/// pre-existing orphan rows also fail. The exact count stays internal.
/// </summary>
public static class NoNewOrphansProperty
{
    public static async Task<PropertyResult> EvaluateAsync(
        EphemeralSession session,
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

            if (rows.Count != 1 || rows[0].LongV is not long count)
            {
                return new PropertyResult("no_new_orphans", PropertyStatus.Error, SavErrorCode.QueryFailed);
            }

            if (count == 0)
            {
                return new PropertyResult("no_new_orphans", PropertyStatus.Pass, null);
            }

            return new PropertyResult(
                "no_new_orphans",
                PropertyStatus.Fail,
                SavErrorCode.OrphansFound);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (SavException ex) when (ex.Code == SavErrorCode.QueryFailed)
        {
            return new PropertyResult("no_new_orphans", PropertyStatus.Fail, SavErrorCode.QueryFailed);
        }
        catch (Exception)
        {
            return new PropertyResult("no_new_orphans", PropertyStatus.Error, SavErrorCode.QueryFailed);
        }
    }
}
