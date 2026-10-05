using Sav.Domain.Contracts;
using Sav.Domain.Policies;
using Sav.Domain.Properties;

namespace Sav.Application.Abstractions;

/// <summary>
/// Shadow migration apply on ephemeral PostgreSQL (Testcontainers). Not for real aliases.
/// </summary>
public interface IShadowMigrationRunner
{
    Task<ShadowMigrationOutcome> RunAsync(
        ShadowMigrationCommand command,
        CancellationToken cancellationToken);
}

/// <summary>
/// Command for an ephemeral shadow migration run.
/// </summary>
public sealed record ShadowMigrationCommand(
    string BaseSchemaSql,
    string MigrationSql,
    string SchemaName,
    IReadOnlyList<PropertySpec> Properties,
    TimeSpan? StatementTimeout,
    DisclosureProfile Disclosure);

/// <summary>
/// Outcome of a shadow migration run. No real-target DSNs or row payloads.
/// </summary>
public sealed record ShadowMigrationOutcome(
    bool Applied,
    bool ContainerDestroyed,
    IReadOnlyList<PropertyResult> PropertyResults,
    string? RedactedError);
