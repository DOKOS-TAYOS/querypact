using Npgsql;
using Sav.Application.Abstractions;
using Sav.Domain.Contracts;
using Sav.Domain.Decisions;
using Sav.Domain.Errors;
using Sav.Domain.Policies;
using Sav.Domain.Properties;
using Sav.Domain.Schema;
using Sav.Infrastructure.Postgres.Oracle;
using Sav.Infrastructure.Postgres.Oracle.Properties;
using Sav.Infrastructure.Postgres.Redaction;
using Testcontainers.PostgreSql;

namespace Sav.Infrastructure.Postgres.Migrations;

/// <summary>
/// Applies migrations only on ephemeral PostgreSQL (Testcontainers).
/// Flow: create container → load base → apply → snapshot → properties → redact → destroy.
/// </summary>
public sealed class ShadowMigrationRunner : IShadowMigrationRunner
{
    // One active shadow container per process, across runner instances and entry points.
    private static readonly SemaphoreSlim ContainerSlot = new(1, 1);
    private const long ContainerMemoryLimitBytes = 1024L * 1024 * 1024;
    private const long ContainerNanoCpus = 2_000_000_000;

    private readonly MinimalStrictRedactor _redactor;

    public ShadowMigrationRunner(MinimalStrictRedactor redactor)
    {
        ArgumentNullException.ThrowIfNull(redactor);
        _redactor = redactor;
    }

    public async Task<ShadowMigrationOutcome> RunAsync(
        ShadowMigrationCommand command,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        ArgumentException.ThrowIfNullOrWhiteSpace(command.BaseSchemaSql);
        ArgumentException.ThrowIfNullOrWhiteSpace(command.MigrationSql);
        ArgumentException.ThrowIfNullOrWhiteSpace(command.SchemaName);
        ArgumentNullException.ThrowIfNull(command.Properties);
        ArgumentNullException.ThrowIfNull(command.Disclosure);
        cancellationToken.ThrowIfCancellationRequested();

        await ContainerSlot.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return await RunWithContainerAsync(command, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            ContainerSlot.Release();
        }
    }

    private async Task<ShadowMigrationOutcome> RunWithContainerAsync(
        ShadowMigrationCommand command,
        CancellationToken cancellationToken)
    {
        PostgreSqlContainer container = new PostgreSqlBuilder("postgres:16-alpine")
            .WithDatabase("sav_shadow")
            .WithUsername("postgres")
            .WithPassword("postgres")
            .WithCreateParameterModifier(parameters =>
            {
                parameters.HostConfig ??= new();
                parameters.HostConfig.Memory = ContainerMemoryLimitBytes;
                parameters.HostConfig.NanoCPUs = ContainerNanoCpus;
            })
            .Build();

        ShadowMigrationOutcome? result = null;
        bool applied = false;
        try
        {
            await container.StartAsync(cancellationToken).ConfigureAwait(false);
            string connectionString = container.GetConnectionString();

            _ = await ExecuteSqlAsync(
                    connectionString,
                    command.BaseSchemaSql,
                    command.StatementTimeout,
                    command.Disclosure,
                    command.BaseSchemaSql,
                    cancellationToken)
                .ConfigureAwait(false);

            bool needsSchemaSnapshot = command.Properties.Any(static spec => spec is SchemaInvariantSpec);
            EphemeralSessionFactory sessionFactory = new(_redactor, command.Disclosure);
            SchemaSnapshotter snapshotter = new();

            SchemaSnapshot? schemaBefore = null;
            if (needsSchemaSnapshot)
            {
                await using EphemeralSession beforeSession = await sessionFactory
                    .OpenAsync(connectionString, cancellationToken)
                    .ConfigureAwait(false);
                schemaBefore = await snapshotter
                    .CaptureAsync(beforeSession, command.SchemaName, cancellationToken)
                    .ConfigureAwait(false);
            }

            long migrationAffectedRows = await ExecuteSqlAsync(
                    connectionString,
                    command.MigrationSql,
                    command.StatementTimeout,
                    command.Disclosure,
                    command.MigrationSql,
                    cancellationToken)
                .ConfigureAwait(false);
            applied = true;

            SchemaSnapshot? schemaAfter = null;
            if (needsSchemaSnapshot)
            {
                await using EphemeralSession afterSession = await sessionFactory
                    .OpenAsync(connectionString, cancellationToken)
                    .ConfigureAwait(false);
                schemaAfter = await snapshotter
                    .CaptureAsync(afterSession, command.SchemaName, cancellationToken)
                    .ConfigureAwait(false);
            }

            IReadOnlyList<PropertyResult> properties = await EvaluatePropertiesAsync(
                    sessionFactory,
                    connectionString,
                    schemaBefore,
                    schemaAfter,
                    migrationAffectedRows,
                    command.Properties,
                    cancellationToken)
                .ConfigureAwait(false);

            result = new ShadowMigrationOutcome(
                Applied: true,
                ContainerDestroyed: false,
                properties,
                RedactedError: null);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            string error = RedactFailure(ex, command);
            result = applied
                ? new ShadowMigrationOutcome(
                    Applied: true,
                    ContainerDestroyed: false,
                    PropertyResults: command.Properties
                        .Select(spec => new PropertyResult(spec.Name, PropertyStatus.Error, error))
                        .ToArray(),
                    RedactedError: null)
                : new ShadowMigrationOutcome(
                    Applied: false,
                    ContainerDestroyed: false,
                    PropertyResults: [],
                    RedactedError: error);
        }
        finally
        {
            await container.DisposeAsync().ConfigureAwait(false);
        }

        return (result ?? new ShadowMigrationOutcome(
            Applied: false,
            ContainerDestroyed: false,
            PropertyResults: [],
            RedactedError: "query_failed")) with
        { ContainerDestroyed = true };
    }

    private static async Task<IReadOnlyList<PropertyResult>> EvaluatePropertiesAsync(
        EphemeralSessionFactory sessionFactory,
        string connectionString,
        SchemaSnapshot? schemaBefore,
        SchemaSnapshot? schemaAfter,
        long migrationAffectedRows,
        IReadOnlyList<PropertySpec> properties,
        CancellationToken cancellationToken)
    {
        List<PropertyResult> results = new(properties.Count);

        foreach (PropertySpec spec in properties)
        {
            cancellationToken.ThrowIfCancellationRequested();
            switch (spec)
            {
                case SchemaInvariantSpec invariant:
                    results.Add(schemaBefore is not null && schemaAfter is not null
                        ? SchemaInvariantProperty.Evaluate(schemaBefore, schemaAfter, invariant)
                        : new PropertyResult(spec.Name, PropertyStatus.Error, SavErrorCode.QueryFailed));
                    break;
                case AffectedRowsSpec affectedRows:
                    results.Add(AffectedRowsProperty.EvaluateCount(
                        migrationAffectedRows,
                        affectedRows.MinInclusive,
                        affectedRows.MaxInclusive));
                    break;
                case NoNewOrphansSpec orphans:
                    {
                        string sql = OracleSqlBoundary.BuildNoNewOrphansCommand(
                            orphans.ParentTable,
                            orphans.ParentKey,
                            orphans.ChildTable,
                            orphans.ChildKey);
                        await using EphemeralSession session = await sessionFactory
                            .OpenAsync(connectionString, cancellationToken)
                            .ConfigureAwait(false);
                        results.Add(await NoNewOrphansProperty
                            .EvaluateAsync(session, sql, cancellationToken)
                            .ConfigureAwait(false));
                        break;
                    }

                default:
                    results.Add(new PropertyResult(spec.Name, PropertyStatus.NotEvaluated, null));
                    break;
            }
        }

        return results;
    }

    private async Task<long> ExecuteSqlAsync(
        string connectionString,
        string sql,
        TimeSpan? statementTimeout,
        DisclosureProfile disclosure,
        string sqlForRedaction,
        CancellationToken cancellationToken)
    {
        await using NpgsqlConnection connection = new(connectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);

        if (statementTimeout is { } timeout)
        {
            int milliseconds = (int)Math.Max(1, timeout.TotalMilliseconds);
            await using NpgsqlCommand setTimeout = new(
                "SELECT set_config('statement_timeout', @ms, false)",
                connection);
            setTimeout.Parameters.AddWithValue(
                "ms",
                milliseconds.ToString(System.Globalization.CultureInfo.InvariantCulture));
            await setTimeout.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        }

        try
        {
            await using NpgsqlCommand command = new(sql, connection);
            int affected = await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
            return affected;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            throw new SavException(
                SavErrorCode.QueryFailed,
                RedactFailure(ex, disclosure, sqlForRedaction));
        }
    }

    private string RedactFailure(Exception ex, ShadowMigrationCommand command)
    {
        return RedactFailure(ex, command.Disclosure, command.MigrationSql, command.BaseSchemaSql);
    }

    /// <summary>
    /// Returns a fixed machine code only. Scrubs free-text for defense-in-depth before coerce;
    /// scrubbed PG primary messages must never become attestation details.
    /// </summary>
    private string RedactFailure(
        Exception ex,
        DisclosureProfile disclosure,
        string primarySql,
        string? secondarySql = null)
    {
        if (ex is SavException sav && FixedPropertyDetailCodes.Contains(sav.Code))
        {
            return sav.Code;
        }

        // Defense-in-depth scrub (logs / intermediate SavException messages); egress is fixed code.
        string message = ex.Message;
        string redacted = _redactor.RedactText(message, disclosure);
        redacted = ScrubSql(redacted, primarySql);
        if (secondarySql is not null)
        {
            redacted = ScrubSql(redacted, secondarySql);
        }

        _ = _redactor.RedactText(redacted, disclosure);
        return SavErrorCode.QueryFailed;
    }

    private static string ScrubSql(string text, string sql)
    {
        string trimmed = sql.Trim();
        if (trimmed.Length == 0)
        {
            return text;
        }

        string result = text.Replace(
            trimmed,
            MinimalStrictRedactor.RedactedToken,
            StringComparison.OrdinalIgnoreCase);
        foreach (string line in trimmed.Split(
                     ['\r', '\n'],
                     StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (line.Length >= 8)
            {
                result = result.Replace(
                    line,
                    MinimalStrictRedactor.RedactedToken,
                    StringComparison.OrdinalIgnoreCase);
            }
        }

        return result.Replace(
            "pg_sleep",
            MinimalStrictRedactor.RedactedToken,
            StringComparison.OrdinalIgnoreCase);
    }
}
