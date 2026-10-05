using Sav.Domain.Contracts;
using Sav.Domain.Decisions;
using Sav.Domain.Errors;
using Sav.Domain.Properties;
using Sav.Domain.Schema;
using Sav.Infrastructure.Postgres.Migrations;
using Sav.Infrastructure.Postgres.Oracle;
using Sav.Infrastructure.Postgres.Oracle.Properties;
using Sav.Infrastructure.Postgres.Tests.Fixtures;

namespace Sav.Infrastructure.Postgres.Tests.Migrations;

[Collection(nameof(PostgresRoCollection))]
public sealed class SchemaSnapshotterAggregateOnlyTests
{
    private readonly PostgresRoFixture _fixture;

    public SchemaSnapshotterAggregateOnlyTests(PostgresRoFixture fixture)
    {
        _fixture = fixture;
    }

    [Fact]
    public void Snapshot_sql_templates_are_aggregate_only()
    {
        Assert.Equal(3, SchemaSnapshotter.AllowListedSqlTemplates.Count);

        foreach (string sql in SchemaSnapshotter.AllowListedSqlTemplates)
        {
            string normalized = sql.ToLowerInvariant();
            Assert.True(
                normalized.Contains("count(", StringComparison.Ordinal)
                || normalized.Contains("string_agg(", StringComparison.Ordinal)
                || normalized.Contains("json_agg(", StringComparison.Ordinal),
                "Expected aggregate template: " + sql);

            Assert.DoesNotContain("select attname,", normalized, StringComparison.Ordinal);
            Assert.DoesNotContain("select *", normalized, StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task Snapshot_captures_counts_digests_and_constraints()
    {
        await _fixture.ExecuteAdminAsync(
            """
            DROP TABLE IF EXISTS snap_child CASCADE;
            DROP TABLE IF EXISTS snap_parent CASCADE;
            CREATE TABLE snap_parent (
              id int PRIMARY KEY,
              label text NOT NULL
            );
            CREATE TABLE snap_child (
              id int PRIMARY KEY,
              parent_id int NOT NULL,
              CONSTRAINT snap_child_parent_fkey FOREIGN KEY (parent_id) REFERENCES snap_parent(id)
            );
            """);

        SchemaSnapshot snapshot = await CaptureAsync("public");

        Assert.Equal("public", snapshot.SchemaName);
        Assert.True(snapshot.RelationCountByRelkind.TryGetValue("r", out long tables));
        Assert.True(tables >= 2);

        AssertDigest(snapshot.RelationDigestByName["public.snap_parent"]);
        AssertDigest(snapshot.RelationDigestByName["public.snap_child"]);
        Assert.Equal("r", snapshot.RelationKindByName["public.snap_parent"]);
        Assert.Equal("r", snapshot.RelationKindByName["public.snap_child"]);

        Assert.True(snapshot.ConstraintExistsByName.TryGetValue("snap_parent_pkey", out bool parentPk));
        Assert.True(parentPk);
        Assert.True(snapshot.ConstraintExistsByName.TryGetValue("snap_child_parent_fkey", out bool fk));
        Assert.True(fk);

        AssertDigest(snapshot.ConstraintDigestByName["public.snap_parent.snap_parent_pkey"]);
        AssertDigest(snapshot.ConstraintDigestByName["public.snap_child.snap_child_parent_fkey"]);
    }

    [Fact]
    public async Task Snapshot_fails_closed_on_unsafe_identifiers()
    {
        await _fixture.ExecuteAdminAsync(
            """
            DROP SCHEMA IF EXISTS snap_semantics CASCADE;
            CREATE SCHEMA snap_semantics;
            CREATE TABLE snap_semantics.snap_alpha (
              id int PRIMARY KEY,
              label text,
              CONSTRAINT snap_alpha_check CHECK (id > 0)
            );
            CREATE TABLE snap_semantics.snap_beta (
              z text,
              a text,
              CONSTRAINT snap_beta_check CHECK (z IS NOT NULL)
            );
            CREATE TABLE snap_semantics.snap_mixed_attribute (
              id int,
              "MixedColumn" text,
              tail text
            );
            CREATE TABLE snap_semantics."MixedRelation" (id int);
            """);

        SavException ex = await Assert.ThrowsAsync<SavException>(
            () => CaptureAsync("snap_semantics"));

        Assert.Equal(SavErrorCode.UnsafeIdentifier, ex.Code);
    }

    [Fact]
    public async Task Snapshot_exposes_only_relkinds_with_relation_digests()
    {
        await _fixture.ExecuteAdminAsync(
            """
            DROP SCHEMA IF EXISTS snap_relkinds CASCADE;
            CREATE SCHEMA snap_relkinds;
            CREATE TABLE snap_relkinds.items (id int);
            CREATE INDEX items_idx ON snap_relkinds.items(id);
            CREATE SEQUENCE snap_relkinds.item_seq;
            """);

        SchemaSnapshot snapshot = await CaptureAsync("snap_relkinds");

        Assert.Equal(1, snapshot.RelationCountByRelkind["r"]);
        Assert.Equal(1, snapshot.RelationCountByRelkind["S"]);
        Assert.False(snapshot.RelationCountByRelkind.ContainsKey("i"));
        Assert.False(snapshot.RelationCountByRelkind.ContainsKey("I"));
        AssertDigest(snapshot.RelationDigestByName["snap_relkinds.items"]);
        AssertDigest(snapshot.RelationDigestByName["snap_relkinds.item_seq"]);
        Assert.Equal("r", snapshot.RelationKindByName["snap_relkinds.items"]);
        Assert.Equal("S", snapshot.RelationKindByName["snap_relkinds.item_seq"]);
        Assert.DoesNotContain("snap_relkinds.items_idx", snapshot.RelationDigestByName.Keys);
        Assert.DoesNotContain("snap_relkinds.items_idx", snapshot.RelationKindByName.Keys);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task View_definition_change_with_same_columns_fails_schema_invariant(bool materialized)
    {
        string schema = materialized ? "snap_matview_def" : "snap_view_def";
        string kind = materialized ? "MATERIALIZED VIEW" : "VIEW";
        string relkind = materialized ? "m" : "v";
        string noData = materialized ? " WITH NO DATA" : string.Empty;

        await _fixture.ExecuteAdminAsync(
            $"""
            DROP SCHEMA IF EXISTS {schema} CASCADE;
            CREATE SCHEMA {schema};
            CREATE TABLE {schema}.items (id int);
            CREATE {kind} {schema}.candidate AS
              SELECT id FROM {schema}.items WHERE id > 0{noData};
            """);

        SchemaSnapshot before = await CaptureAsync(schema);
        string beforeDigest = before.RelationDigestByName[schema + ".candidate"];

        if (materialized)
        {
            await _fixture.ExecuteAdminAsync(
                $"DROP MATERIALIZED VIEW {schema}.candidate; "
                + $"CREATE MATERIALIZED VIEW {schema}.candidate AS "
                + $"SELECT id FROM {schema}.items WHERE id >= 0 WITH NO DATA;");
        }
        else
        {
            await _fixture.ExecuteAdminAsync(
                $"CREATE OR REPLACE VIEW {schema}.candidate AS "
                + $"SELECT id FROM {schema}.items WHERE id >= 0;");
        }

        SchemaSnapshot after = await CaptureAsync(schema);
        string afterDigest = after.RelationDigestByName[schema + ".candidate"];

        Assert.NotEqual(beforeDigest, afterDigest);
        PropertyResult result = SchemaInvariantProperty.Evaluate(
            before,
            after,
            new SchemaInvariantSpec([new SchemaInvariantRequirement("candidate", relkind)]));
        Assert.Equal(PropertyStatus.Fail, result.Status);
        Assert.Equal(SavErrorCode.SchemaInvariantFailed, result.RedactedDetail);
    }

    [Fact]
    public async Task Digest_changes_when_column_added()
    {
        await _fixture.ExecuteAdminAsync(
            """
            DROP TABLE IF EXISTS snap_digest CASCADE;
            CREATE TABLE snap_digest (
              id int PRIMARY KEY
            );
            """);

        string beforeDigest = (await CaptureAsync("public"))
            .RelationDigestByName["public.snap_digest"];

        await _fixture.ExecuteAdminAsync("ALTER TABLE snap_digest ADD COLUMN note text;");

        string afterDigest = (await CaptureAsync("public"))
            .RelationDigestByName["public.snap_digest"];

        Assert.NotEqual(beforeDigest, afterDigest);
    }

    [Fact]
    public async Task Digest_changes_when_column_type_nullability_or_default_changes()
    {
        await _fixture.ExecuteAdminAsync(
            """
            DROP TABLE IF EXISTS snap_column_semantics CASCADE;
            CREATE TABLE snap_column_semantics (
              id int PRIMARY KEY,
              value varchar(10) NOT NULL DEFAULT 'a'
            );
            """);

        string baseline = (await CaptureAsync("public"))
            .RelationDigestByName["public.snap_column_semantics"];

        await _fixture.ExecuteAdminAsync(
            "ALTER TABLE snap_column_semantics ALTER COLUMN value TYPE varchar(20);");
        string typeChanged = (await CaptureAsync("public"))
            .RelationDigestByName["public.snap_column_semantics"];
        Assert.NotEqual(baseline, typeChanged);

        await _fixture.ExecuteAdminAsync(
            "ALTER TABLE snap_column_semantics ALTER COLUMN value DROP NOT NULL;");
        string nullabilityChanged = (await CaptureAsync("public"))
            .RelationDigestByName["public.snap_column_semantics"];
        Assert.NotEqual(typeChanged, nullabilityChanged);

        await _fixture.ExecuteAdminAsync(
            "ALTER TABLE snap_column_semantics ALTER COLUMN value SET DEFAULT 'b';");
        string defaultChanged = (await CaptureAsync("public"))
            .RelationDigestByName["public.snap_column_semantics"];
        Assert.NotEqual(nullabilityChanged, defaultChanged);
    }

    [Fact]
    public async Task Constraint_digest_changes_when_same_named_definition_changes()
    {
        await _fixture.ExecuteAdminAsync(
            """
            DROP TABLE IF EXISTS snap_constraint CASCADE;
            CREATE TABLE snap_constraint (
              value int,
              CONSTRAINT snap_rule CHECK (value > 0)
            );
            """);

        SchemaSnapshot before = await CaptureAsync("public");
        string beforeDigest = before.ConstraintDigestByName["public.snap_constraint.snap_rule"];
        Assert.True(before.ConstraintExistsByName["snap_rule"]);

        await _fixture.ExecuteAdminAsync(
            """
            ALTER TABLE snap_constraint DROP CONSTRAINT snap_rule;
            ALTER TABLE snap_constraint ADD CONSTRAINT snap_rule CHECK (value >= 0);
            """);

        SchemaSnapshot after = await CaptureAsync("public");
        string afterDigest = after.ConstraintDigestByName["public.snap_constraint.snap_rule"];

        Assert.True(after.ConstraintExistsByName["snap_rule"]);
        Assert.NotEqual(beforeDigest, afterDigest);
    }

    [Fact]
    public async Task Empty_schema_and_relation_capture_stable_digests()
    {
        await _fixture.ExecuteAdminAsync(
            """
            DROP SCHEMA IF EXISTS snap_empty CASCADE;
            CREATE SCHEMA snap_empty;
            """);

        SchemaSnapshot empty = await CaptureAsync("snap_empty");
        Assert.Empty(empty.RelationCountByRelkind);
        Assert.Empty(empty.RelationDigestByName);
        Assert.Empty(empty.RelationKindByName);
        Assert.Empty(empty.ConstraintExistsByName);
        Assert.Empty(empty.ConstraintDigestByName);

        await _fixture.ExecuteAdminAsync("CREATE TABLE snap_empty.no_columns ();");

        SchemaSnapshot first = await CaptureAsync("snap_empty");
        SchemaSnapshot second = await CaptureAsync("snap_empty");
        Assert.Equal(1, first.RelationCountByRelkind["r"]);
        AssertDigest(first.RelationDigestByName["snap_empty.no_columns"]);
        Assert.Equal("r", first.RelationKindByName["snap_empty.no_columns"]);
        Assert.Equal(
            first.RelationDigestByName["snap_empty.no_columns"],
            second.RelationDigestByName["snap_empty.no_columns"]);
        Assert.Empty(first.ConstraintDigestByName);
    }

    [Fact]
    public async Task Same_named_constraints_on_different_relations_have_distinct_stable_keys()
    {
        await _fixture.ExecuteAdminAsync(
            """
            DROP SCHEMA IF EXISTS snap_repeated CASCADE;
            CREATE SCHEMA snap_repeated;
            CREATE TABLE snap_repeated.first (
              value int,
              CONSTRAINT shared_rule CHECK (value > 0)
            );
            CREATE TABLE snap_repeated.second (
              value int,
              CONSTRAINT shared_rule CHECK (value >= 0)
            );
            """);

        SchemaSnapshot first = await CaptureAsync("snap_repeated");
        SchemaSnapshot second = await CaptureAsync("snap_repeated");

        Assert.True(first.ConstraintExistsByName["shared_rule"]);
        Assert.Equal(2, first.ConstraintDigestByName.Count);
        AssertDigest(first.ConstraintDigestByName["snap_repeated.first.shared_rule"]);
        AssertDigest(first.ConstraintDigestByName["snap_repeated.second.shared_rule"]);
        Assert.NotEqual(
            first.ConstraintDigestByName["snap_repeated.first.shared_rule"],
            first.ConstraintDigestByName["snap_repeated.second.shared_rule"]);
        Assert.Equal(
            first.ConstraintDigestByName["snap_repeated.first.shared_rule"],
            second.ConstraintDigestByName["snap_repeated.first.shared_rule"]);
        Assert.Equal(
            first.ConstraintDigestByName["snap_repeated.second.shared_rule"],
            second.ConstraintDigestByName["snap_repeated.second.shared_rule"]);
    }

    [Fact]
    public async Task Identity_generated_and_collation_metadata_capture_stably()
    {
        await _fixture.ExecuteAdminAsync(
            """
            DROP SCHEMA IF EXISTS snap_metadata CASCADE;
            CREATE SCHEMA snap_metadata;
            CREATE TABLE snap_metadata.metadata (
              id int GENERATED ALWAYS AS IDENTITY,
              value text COLLATE "C",
              derived text GENERATED ALWAYS AS (value || '!') STORED
            );
            """);

        SchemaSnapshot first = await CaptureAsync("snap_metadata");
        SchemaSnapshot second = await CaptureAsync("snap_metadata");
        string baseline = first.RelationDigestByName["snap_metadata.metadata"];
        AssertDigest(baseline);
        Assert.Equal(baseline, second.RelationDigestByName["snap_metadata.metadata"]);

        await _fixture.ExecuteAdminAsync(
            "ALTER TABLE snap_metadata.metadata ALTER COLUMN id SET GENERATED BY DEFAULT;");
        SchemaSnapshot changed = await CaptureAsync("snap_metadata");
        Assert.NotEqual(baseline, changed.RelationDigestByName["snap_metadata.metadata"]);
    }

    private async Task<SchemaSnapshot> CaptureAsync(string schema)
    {
        EphemeralSessionFactory factory = new(_fixture.Redactor, _fixture.StrictDisclosure);
        await using EphemeralSession session = await factory
            .OpenAsync(_fixture.AdminConnectionString, CancellationToken.None);

        return await new SchemaSnapshotter()
            .CaptureAsync(session, schema, CancellationToken.None);
    }

    private static void AssertDigest(string digest)
    {
        Assert.Matches("^[0-9a-f]{64}$", digest);
    }
}
