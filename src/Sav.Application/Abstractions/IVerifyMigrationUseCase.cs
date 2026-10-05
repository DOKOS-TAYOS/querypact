using Sav.Application.Migrations;

namespace Sav.Application.Abstractions;

public interface IVerifyMigrationUseCase
{
    Task<VerifyMigrationResponse> ExecuteAsync(
        VerifyMigrationRequest request,
        CancellationToken cancellationToken);
}
