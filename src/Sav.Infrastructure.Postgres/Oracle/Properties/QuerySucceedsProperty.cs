using Sav.Application.Abstractions;
using Sav.Domain.Decisions;
using Sav.Domain.Errors;
using Sav.Domain.Properties;

namespace Sav.Infrastructure.Postgres.Oracle.Properties;

/// <summary>
/// <c>query_succeeds</c>: Pass when the full row-producing command runs without a PostgreSQL error.
/// The wrapper consumes the complete composite result server-side; the scalar count is never disclosed.
/// </summary>
public static class QuerySucceedsProperty
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
            // Materialize scalar v only to keep the closed reader shape; value is intentionally ignored.
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
            return new PropertyResult("query_succeeds", PropertyStatus.Fail, SavErrorCode.QueryFailed);
        }
        catch (SavException)
        {
            return new PropertyResult("query_succeeds", PropertyStatus.Error, SavErrorCode.QueryFailed);
        }
        catch (Exception)
        {
            return new PropertyResult("query_succeeds", PropertyStatus.Error, SavErrorCode.QueryFailed);
        }
    }

    internal static PropertyResult MapRows(IReadOnlyList<OracleScalarRow> rows)
    {
        ArgumentNullException.ThrowIfNull(rows);
        return new PropertyResult("query_succeeds", PropertyStatus.Pass, null);
    }
}
