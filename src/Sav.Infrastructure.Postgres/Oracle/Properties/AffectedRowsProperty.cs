using Sav.Domain.Decisions;
using Sav.Domain.Errors;
using Sav.Domain.Properties;

namespace Sav.Infrastructure.Postgres.Oracle.Properties;

/// <summary>
/// <c>affected_rows</c>: ephemeral-only direct DML; compares RecordsAffected to Min/Max inclusive.
/// </summary>
public static class AffectedRowsProperty
{
    public static PropertyResult EvaluateCount(
        long affected,
        long minInclusive,
        long? maxInclusive)
    {
        if (maxInclusive is long max && max < minInclusive)
        {
            return new PropertyResult(
                "affected_rows",
                PropertyStatus.Error,
                SavErrorCode.UnsupportedConstruct);
        }

        bool inRange = affected >= minInclusive
            && (maxInclusive is null || affected <= maxInclusive.Value);

        return inRange
            ? new PropertyResult("affected_rows", PropertyStatus.Pass, null)
            : new PropertyResult(
                "affected_rows",
                PropertyStatus.Fail,
                SavErrorCode.AffectedRowsOutOfRange);
    }

    public static async Task<PropertyResult> EvaluateAsync(
        EphemeralSession session,
        string dmlSql,
        long minInclusive,
        long? maxInclusive,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(session);
        ArgumentException.ThrowIfNullOrWhiteSpace(dmlSql);
        cancellationToken.ThrowIfCancellationRequested();

        try
        {
            long affected = await session.ExecuteDmlAsync(dmlSql, cancellationToken).ConfigureAwait(false);
            return EvaluateCount(affected, minInclusive, maxInclusive);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (SavException ex) when (ex.Code == SavErrorCode.QueryFailed)
        {
            return new PropertyResult("affected_rows", PropertyStatus.Fail, SavErrorCode.QueryFailed);
        }
        catch (Exception)
        {
            return new PropertyResult("affected_rows", PropertyStatus.Error, SavErrorCode.QueryFailed);
        }
    }
}
