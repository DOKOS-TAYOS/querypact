using Sav.Application.Abstractions;

namespace Sav.Infrastructure.Postgres.Targets;

internal interface IOracleBatchReadSession
{
    Task<IReadOnlyList<IReadOnlyList<OracleScalarRow>>> ExecuteBatchAsync(
        IReadOnlyList<OracleBatchReadCommand> commands,
        CancellationToken cancellationToken);
}

internal sealed record OracleBatchReadCommand(
    string Sql,
    IReadOnlyList<OracleScalarColumn> AllowedColumns);
