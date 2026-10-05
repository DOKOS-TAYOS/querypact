using Sav.Application.Abstractions;
using Sav.Domain.Contracts;
using Sav.Domain.Decisions;
using Sav.Domain.Errors;
using Sav.Domain.Policies;
using Sav.Domain.Properties;
using Sav.Infrastructure.Postgres.Migrations;
using Sav.Infrastructure.Postgres.Redaction;

namespace Sav.Infrastructure.Postgres.Tests.Migrations;

public sealed class ShadowMigrationRunnerTests
{
    private static readonly DisclosureProfile Strict = new(
        "strict",
        IncludePlanSummary: false,
        IncludeObjectNames: false,
        IncludeTimings: false,
        IncludeRowCounts: false);

    private static readonly SchemaInvariantSpec DefaultInvariant = new(
    [
        new SchemaInvariantRequirement("orders", "r"),
        new SchemaInvariantRequirement("order_items", "r"),
    ]);

    private static readonly NoNewOrphansSpec DefaultOrphans = new(
        "orders",
        "id",
        "order_items",
        "order_id");

    [Fact]
    public async Task Valid_migration_applies_and_properties_pass()
    {
        ShadowMigrationRunner runner = CreateRunner();
        ShadowMigrationOutcome result = await runner.RunAsync(
            new ShadowMigrationCommand(
                ShadowMigrationBaseSchema.Sql,
                MigrationFixturePath.Read("valid", "up.sql"),
                "public",
                [DefaultInvariant, DefaultOrphans],
                StatementTimeout: TimeSpan.FromSeconds(5),
                Strict),
            CancellationToken.None);

        Assert.True(result.ContainerDestroyed);
        Assert.True(result.Applied);
        Assert.Null(result.RedactedError);
        Assert.All(result.PropertyResults, p => Assert.Equal(PropertyStatus.Pass, p.Status));
    }

    [Fact]
    public async Task Concurrent_runners_share_the_slot_and_cancel_a_waiting_request()
    {
        ShadowMigrationRunner firstRunner = CreateRunner();
        ShadowMigrationRunner secondRunner = CreateRunner();
        ShadowMigrationCommand command = new(
            ShadowMigrationBaseSchema.Sql,
            "SELECT pg_sleep(1)",
            "public",
            [DefaultOrphans],
            StatementTimeout: TimeSpan.FromSeconds(5),
            Strict);

        Task<ShadowMigrationOutcome> running = firstRunner.RunAsync(command, CancellationToken.None);
        using CancellationTokenSource cancellation = new();
        Task<ShadowMigrationOutcome> waiting = secondRunner.RunAsync(command, cancellation.Token);
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => waiting);

        ShadowMigrationOutcome result = await running;
        Assert.True(result.Applied);
        Assert.True(result.ContainerDestroyed);
        Assert.All(result.PropertyResults, property => Assert.Equal(PropertyStatus.Pass, property.Status));
    }

    [Fact]
    public async Task Affected_rows_uses_the_existing_migration_execution_result()
    {
        ShadowMigrationRunner runner = CreateRunner();
        ShadowMigrationOutcome result = await runner.RunAsync(
            new ShadowMigrationCommand(
                ShadowMigrationBaseSchema.Sql,
                "INSERT INTO orders (id, amount) VALUES (3, 30)",
                "public",
                [new AffectedRowsSpec(1, 1)],
                StatementTimeout: TimeSpan.FromSeconds(5),
                Strict),
            CancellationToken.None);

        Assert.True(result.ContainerDestroyed);
        Assert.True(result.Applied);
        Assert.Equal(
            new PropertyResult("affected_rows", PropertyStatus.Pass, null),
            Assert.Single(result.PropertyResults));
    }

    [Fact]
    public async Task Affected_rows_does_not_capture_unneeded_schema_metadata()
    {
        ShadowMigrationRunner runner = CreateRunner();
        string baseSchema = ShadowMigrationBaseSchema.Sql
            + """

            CREATE TABLE quoted_metadata (
              id int PRIMARY KEY,
              "DisplayName" text
            );
            """;

        ShadowMigrationOutcome result = await runner.RunAsync(
            new ShadowMigrationCommand(
                baseSchema,
                "INSERT INTO orders (id, amount) VALUES (3, 30)",
                "public",
                [new AffectedRowsSpec(1, 1)],
                StatementTimeout: TimeSpan.FromSeconds(5),
                Strict),
            CancellationToken.None);

        Assert.True(result.ContainerDestroyed);
        Assert.True(result.Applied);
        Assert.Null(result.RedactedError);
        Assert.Equal(
            new PropertyResult("affected_rows", PropertyStatus.Pass, null),
            Assert.Single(result.PropertyResults));
    }

    [Fact]
    public async Task Property_failure_after_apply_preserves_applied_state()
    {
        ShadowMigrationRunner runner = CreateRunner();
        ShadowMigrationOutcome result = await runner.RunAsync(
            new ShadowMigrationCommand(
                ShadowMigrationBaseSchema.Sql,
                "INSERT INTO orders (id, amount) VALUES (3, 30)",
                "public",
                [new NoNewOrphansSpec("invalid;table", "id", "order_items", "order_id")],
                StatementTimeout: TimeSpan.FromSeconds(5),
                Strict),
            CancellationToken.None);

        Assert.True(result.ContainerDestroyed);
        Assert.True(result.Applied);
        Assert.Null(result.RedactedError);
        Assert.Equal(
            new PropertyResult("no_new_orphans", PropertyStatus.Error, SavErrorCode.UnsafeIdentifier),
            Assert.Single(result.PropertyResults));
    }

    [Fact]
    public async Task Post_apply_snapshot_failure_preserves_applied_state()
    {
        ShadowMigrationRunner runner = CreateRunner();
        ShadowMigrationOutcome result = await runner.RunAsync(
            new ShadowMigrationCommand(
                ShadowMigrationBaseSchema.Sql,
                "ALTER TABLE orders ADD COLUMN \"DisplayName\" text",
                "public",
                [DefaultInvariant],
                StatementTimeout: TimeSpan.FromSeconds(5),
                Strict),
            CancellationToken.None);

        Assert.True(result.ContainerDestroyed);
        Assert.True(result.Applied);
        Assert.Null(result.RedactedError);
        Assert.Equal(
            new PropertyResult("schema_invariant", PropertyStatus.Error, SavErrorCode.UnsafeIdentifier),
            Assert.Single(result.PropertyResults));
    }

    [Fact]
    public async Task Mixed_case_column_in_snapshot_fails_closed()
    {
        ShadowMigrationRunner runner = CreateRunner();
        string baseSchema = ShadowMigrationBaseSchema.Sql
            + """

            CREATE TABLE quoted_metadata (
              id int PRIMARY KEY,
              "DisplayName" text
            );
            """;

        ShadowMigrationOutcome result = await runner.RunAsync(
            new ShadowMigrationCommand(
                baseSchema,
                "SELECT 1;",
                "public",
                [DefaultInvariant],
                StatementTimeout: TimeSpan.FromSeconds(5),
                Strict),
            CancellationToken.None);

        Assert.True(result.ContainerDestroyed);
        Assert.False(result.Applied);
        Assert.Equal(SavErrorCode.UnsafeIdentifier, result.RedactedError);
        Assert.Empty(result.PropertyResults);
    }

    [Fact]
    public async Task Mixed_case_constraint_in_snapshot_fails_closed()
    {
        ShadowMigrationRunner runner = CreateRunner();
        string baseSchema = ShadowMigrationBaseSchema.Sql
            + """

            CREATE TABLE constraint_metadata (
              id int PRIMARY KEY,
              CONSTRAINT "PositiveId" CHECK (id > 0)
            );
            """;

        ShadowMigrationOutcome result = await runner.RunAsync(
            new ShadowMigrationCommand(
                baseSchema,
                "SELECT 1;",
                "public",
                [DefaultInvariant],
                StatementTimeout: TimeSpan.FromSeconds(5),
                Strict),
            CancellationToken.None);

        Assert.True(result.ContainerDestroyed);
        Assert.False(result.Applied);
        Assert.Equal(SavErrorCode.UnsafeIdentifier, result.RedactedError);
        Assert.Empty(result.PropertyResults);
    }

    [Fact]
    public async Task Invalid_sql_fails_closed_with_redacted_error()
    {
        ShadowMigrationRunner runner = CreateRunner();
        ShadowMigrationOutcome result = await runner.RunAsync(
            new ShadowMigrationCommand(
                ShadowMigrationBaseSchema.Sql,
                MigrationFixturePath.Read("invalid", "bad.sql"),
                "public",
                [DefaultInvariant, DefaultOrphans],
                StatementTimeout: TimeSpan.FromSeconds(5),
                Strict),
            CancellationToken.None);

        Assert.True(result.ContainerDestroyed);
        Assert.False(result.Applied);
        Assert.Equal(SavErrorCode.QueryFailed, result.RedactedError);
        Assert.DoesNotContain("password", result.RedactedError!, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Host=", result.RedactedError!, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("at Npgsql", result.RedactedError!, StringComparison.Ordinal);
        Assert.Empty(result.PropertyResults);
    }

    [Fact]
    public async Task Dropped_constraint_fails_schema_invariant()
    {
        ShadowMigrationRunner runner = CreateRunner();
        ShadowMigrationOutcome result = await runner.RunAsync(
            new ShadowMigrationCommand(
                ShadowMigrationBaseSchema.Sql,
                MigrationFixturePath.Read("drops-constraint", "up.sql"),
                "public",
                [DefaultInvariant, DefaultOrphans],
                StatementTimeout: TimeSpan.FromSeconds(5),
                Strict),
            CancellationToken.None);

        Assert.True(result.ContainerDestroyed);
        Assert.True(result.Applied);
        PropertyResult invariant = Assert.Single(
            result.PropertyResults,
            p => p.Name == "schema_invariant");
        Assert.Equal(PropertyStatus.Fail, invariant.Status);
        Assert.Equal(SavErrorCode.SchemaInvariantFailed, invariant.RedactedDetail);
    }

    [Fact]
    public async Task Same_named_constraint_definition_change_fails_schema_invariant()
    {
        ShadowMigrationRunner runner = CreateRunner();
        ShadowMigrationOutcome result = await runner.RunAsync(
            new ShadowMigrationCommand(
                ShadowMigrationBaseSchema.Sql,
                """
                ALTER TABLE orders DROP CONSTRAINT orders_amount_positive;
                ALTER TABLE orders
                  ADD CONSTRAINT orders_amount_positive CHECK (amount >= 0);
                """,
                "public",
                [DefaultInvariant],
                StatementTimeout: TimeSpan.FromSeconds(5),
                Strict),
            CancellationToken.None);

        Assert.True(result.ContainerDestroyed);
        Assert.True(result.Applied);
        PropertyResult invariant = Assert.Single(result.PropertyResults);
        Assert.Equal("schema_invariant", invariant.Name);
        Assert.Equal(PropertyStatus.Fail, invariant.Status);
        Assert.Equal(SavErrorCode.SchemaInvariantFailed, invariant.RedactedDetail);
    }

    [Fact]
    public async Task Nullable_child_key_does_not_fail_no_new_orphans()
    {
        ShadowMigrationRunner runner = CreateRunner();
        string nullableFkSchema = ShadowMigrationBaseSchema.Sql.Replace(
            "order_id int NOT NULL",
            "order_id int",
            StringComparison.Ordinal);
        ShadowMigrationOutcome result = await runner.RunAsync(
            new ShadowMigrationCommand(
                nullableFkSchema,
                "INSERT INTO order_items (id, order_id) VALUES (3, NULL)",
                "public",
                [DefaultOrphans],
                StatementTimeout: TimeSpan.FromSeconds(5),
                Strict),
            CancellationToken.None);

        Assert.True(result.ContainerDestroyed);
        Assert.True(result.Applied);
        Assert.Equal(
            new PropertyResult("no_new_orphans", PropertyStatus.Pass, null),
            Assert.Single(result.PropertyResults));
    }

    [Fact]
    public async Task Broken_fk_fails_no_new_orphans()
    {
        ShadowMigrationRunner runner = CreateRunner();
        ShadowMigrationOutcome result = await runner.RunAsync(
            new ShadowMigrationCommand(
                ShadowMigrationBaseSchema.Sql,
                MigrationFixturePath.Read("breaks-fk", "up.sql"),
                "public",
                [DefaultInvariant, DefaultOrphans],
                StatementTimeout: TimeSpan.FromSeconds(5),
                Strict),
            CancellationToken.None);

        Assert.True(result.ContainerDestroyed);
        Assert.True(result.Applied);
        PropertyResult orphans = Assert.Single(
            result.PropertyResults,
            p => p.Name == "no_new_orphans");
        Assert.Equal(PropertyStatus.Fail, orphans.Status);
        Assert.Equal(SavErrorCode.OrphansFound, orphans.RedactedDetail);
        Assert.DoesNotContain("999", orphans.RedactedDetail!, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Statement_timeout_is_redacted_and_container_destroyed()
    {
        ShadowMigrationRunner runner = CreateRunner();
        ShadowMigrationOutcome result = await runner.RunAsync(
            new ShadowMigrationCommand(
                ShadowMigrationBaseSchema.Sql,
                MigrationFixturePath.Read("timeout", "up.sql"),
                "public",
                [DefaultInvariant, DefaultOrphans],
                StatementTimeout: TimeSpan.FromMilliseconds(500),
                Strict),
            CancellationToken.None);

        Assert.True(result.ContainerDestroyed);
        Assert.False(result.Applied);
        Assert.Equal(SavErrorCode.QueryFailed, result.RedactedError);
        Assert.DoesNotContain("pg_sleep", result.RedactedError!, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Host=", result.RedactedError!, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Cleanup_destroys_container_even_when_base_schema_fails()
    {
        ShadowMigrationRunner runner = CreateRunner();
        ShadowMigrationOutcome result = await runner.RunAsync(
            new ShadowMigrationCommand(
                "THIS BASE SCHEMA IS INVALID;",
                MigrationFixturePath.Read("valid", "up.sql"),
                "public",
                [DefaultInvariant, DefaultOrphans],
                StatementTimeout: TimeSpan.FromSeconds(5),
                Strict),
            CancellationToken.None);

        Assert.True(result.ContainerDestroyed);
        Assert.False(result.Applied);
        Assert.NotNull(result.RedactedError);
    }

    [Fact]
    public async Task Never_uses_real_alias_connection_strings()
    {
        string source = typeof(ShadowMigrationRunner).Assembly.Location;
        Assert.Contains("Sav.Infrastructure.Postgres", source, StringComparison.Ordinal);
        Assert.Null(typeof(ShadowMigrationRunner).GetProperty("TargetAlias"));
        Assert.DoesNotContain(
            "ITargetAliasResolver",
            File.ReadAllText(FindSource("ShadowMigrationRunner.cs")),
            StringComparison.Ordinal);
        Assert.Contains(typeof(IShadowMigrationRunner), typeof(ShadowMigrationRunner).GetInterfaces());
    }

    private static ShadowMigrationRunner CreateRunner()
    {
        return new ShadowMigrationRunner(new MinimalStrictRedactor());
    }

    private static string FindSource(string fileName)
    {
        string? dir = AppContext.BaseDirectory;
        while (dir is not null)
        {
            string candidate = Path.Combine(
                dir,
                "src",
                "Sav.Infrastructure.Postgres",
                "Migrations",
                fileName);
            if (File.Exists(candidate))
            {
                return candidate;
            }

            dir = Directory.GetParent(dir)?.FullName;
        }

        throw new InvalidOperationException(fileName + " source not found.");
    }
}
