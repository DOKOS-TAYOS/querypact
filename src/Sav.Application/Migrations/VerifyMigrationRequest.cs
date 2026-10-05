namespace Sav.Application.Migrations;

/// <summary>
/// Exactly one of <see cref="MigrationSql"/> or <see cref="MigrationPath"/> must be non-null (XOR).
/// Paths never carry body; the use case reads file contents after <c>IConfigPathResolver</c>.
/// </summary>
public sealed record VerifyMigrationRequest(
    string? MigrationSql,
    string? MigrationPath,
    string BaseSchemaPath,
    string PolicyPath,
    string ContractPath);
