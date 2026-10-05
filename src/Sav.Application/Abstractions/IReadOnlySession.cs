namespace Sav.Application.Abstractions;

/// <summary>
/// Typed read-only session. Pipeline opens exactly one per verify Allow path.
/// Does not expose Npgsql / DbDataReader / object? / open dictionaries to Application.
/// </summary>
public interface IReadOnlySession : IAsyncDisposable
{
    Task ExecuteAsync(string sql, CancellationToken cancellationToken);

    Task<IReadOnlyList<OracleScalarRow>> ExecuteReaderAsync(
        string sql,
        IReadOnlyList<OracleScalarColumn> allowedColumns,
        CancellationToken cancellationToken);
}
