using System.Reflection;
using Sav.Application.Abstractions;
using Sav.Domain.Analysis;
using Sav.Domain.Decisions;
using Sav.Domain.Policies;
using Sav.Domain.Targets;
using Sav.Infrastructure.Config.Policies;
using Sav.Infrastructure.Postgres.Catalog;
using Sav.Infrastructure.Postgres.Parsing;
using Sav.Infrastructure.Postgres.Targets;
using Sav.Infrastructure.Postgres.Tests.Fixtures;

namespace Sav.Infrastructure.Postgres.Tests.Catalog;

[Collection(nameof(PostgresRoCollection))]
public sealed class PgCatalogResolverTests
{
    private readonly PostgresRoFixture _fixture;

    public PgCatalogResolverTests(PostgresRoFixture fixture)
    {
        _fixture = fixture;
    }

    [Fact]
    public async Task Enrich_removes_existing_relation_from_unresolved()
    {
        await _fixture.ExecuteAdminAsync(
            """
            CREATE TABLE IF NOT EXISTS public.catalog_users (id int PRIMARY KEY);
            GRANT SELECT ON public.catalog_users TO sav_ro;
            """);

        await using ReadOnlySessionFactory factory = _fixture.CreateFactory();
        TargetAlias alias = _fixture.Resolve(PostgresRoFixture.RoAlias);
        await using IReadOnlySession session =
            await factory.OpenReadOnlySessionAsync(alias, CancellationToken.None);

        LibPgQuerySqlParser parser = new();
        SqlParseResult parse = parser.Parse("SELECT id FROM catalog_users", CancellationToken.None);
        Assert.True(parse.Success);
        Assert.Contains("catalog_users", parse.Ir!.UnresolvedObjects, StringComparer.OrdinalIgnoreCase);

        PgCatalogResolver resolver = new();
        SqlAnalysis enriched = await resolver.EnrichAsync(
            new SqlAnalysis(parse.Ir, true),
            alias,
            session,
            CancellationToken.None);

        Assert.DoesNotContain(
            "catalog_users",
            enriched.Ir.UnresolvedObjects,
            StringComparer.OrdinalIgnoreCase);
        Assert.DoesNotContain("unsupported_construct", enriched.Ir.RiskCodes, StringComparer.Ordinal);
        Assert.Null(typeof(SqlAnalysis).GetProperty("TargetSchemaFingerprint"));
        Assert.Null(typeof(SqlAnalysis).GetProperty("SchemaFingerprint"));
    }

    [Fact]
    public async Task Enrich_rejects_views_and_materialized_views_without_exposing_base_tables()
    {
        await _fixture.ExecuteAdminAsync(
            """
            DROP VIEW IF EXISTS public.sav_bug019_regular_view CASCADE;
            DROP MATERIALIZED VIEW IF EXISTS public.sav_bug019_materialized_view CASCADE;
            DROP SCHEMA IF EXISTS bug019_shadow CASCADE;
            DROP TABLE IF EXISTS public.sav_bug019_denied_base CASCADE;
            DROP TABLE IF EXISTS public.sav_bug019_regular_table CASCADE;
            DROP TABLE IF EXISTS public.sav_bug019_shadowed_table CASCADE;
            CREATE TABLE public.sav_bug019_denied_base (id int);
            CREATE VIEW public.sav_bug019_regular_view AS
              SELECT id FROM public.sav_bug019_denied_base;
            CREATE MATERIALIZED VIEW public.sav_bug019_materialized_view AS
              SELECT id FROM public.sav_bug019_denied_base;
            CREATE TABLE public.sav_bug019_regular_table (id int);
            CREATE TABLE public.sav_bug019_shadowed_table (id int);
            CREATE SCHEMA bug019_shadow;
            CREATE VIEW bug019_shadow.sav_bug019_shadowed_table AS SELECT 1 AS id;
            GRANT SELECT ON public.sav_bug019_regular_view,
              public.sav_bug019_materialized_view TO sav_ro;
            """);

        await using ReadOnlySessionFactory factory = _fixture.CreateFactory();
        TargetAlias alias = _fixture.Resolve(PostgresRoFixture.RoAlias);
        await using IReadOnlySession session = await factory.OpenReadOnlySessionAsync(alias, CancellationToken.None);
        LibPgQuerySqlParser parser = new();
        YamlPolicyEngine policyEngine = new();
        Policy policy = new(
            id: "bug019-policy",
            version: "1",
            allowedStatementTypes: ["Select"],
            deniedTables: ["sav_bug019_denied_base"],
            deniedColumns: [],
            allowedFunctions: [],
            denyUnresolvedObjects: false,
            denyMultipleStatements: true,
            denyUpdateDeleteWithoutPredicate: true,
            maxCostBucket: "high",
            forbiddenPlanNodes: [],
            disclosure: _fixture.StrictDisclosure);

        foreach (string relation in new[]
                 {
                     "sav_bug019_regular_view",
                     "sav_bug019_materialized_view",
                 })
        {
            SqlParseResult parsed = parser.Parse($"SELECT id FROM {relation}", CancellationToken.None);
            Assert.True(parsed.Success, parsed.RedactedMessage);
            Assert.Contains(relation, parsed.Ir!.TablesRead, StringComparer.Ordinal);
            Assert.DoesNotContain("sav_bug019_denied_base", parsed.Ir.TablesRead, StringComparer.Ordinal);

            SqlAnalysis initial = new(parsed.Ir, true);
            PolicyDecision firstPass = await policyEngine.EvaluateAsync(initial, policy, CancellationToken.None);
            Assert.Equal(PolicyOutcome.Allow, firstPass.Outcome);

            SqlAnalysis enriched = await new PgCatalogResolver().EnrichAsync(
                initial,
                alias,
                session,
                CancellationToken.None);

            Assert.Contains("unsupported_construct", enriched.Ir.RiskCodes, StringComparer.Ordinal);
            PolicyDecision secondPass = await policyEngine.EvaluateAsync(enriched, policy, CancellationToken.None);
            Assert.Equal(PolicyOutcome.Deny, secondPass.Outcome);
            Assert.Contains("unsupported_construct", secondPass.RuleIds, StringComparer.Ordinal);
        }

        foreach (string systemViewSql in new[]
                 {
                     "SELECT tablename FROM pg_catalog.pg_views",
                     "SELECT table_name FROM information_schema.tables",
                 })
        {
            SqlParseResult parsed = parser.Parse(systemViewSql, CancellationToken.None);
            Assert.True(parsed.Success, parsed.RedactedMessage);

            SqlAnalysis initial = new(parsed.Ir!, true);
            PolicyDecision firstPass = await policyEngine.EvaluateAsync(initial, policy, CancellationToken.None);
            Assert.Equal(PolicyOutcome.Allow, firstPass.Outcome);

            SqlAnalysis enriched = await new PgCatalogResolver().EnrichAsync(
                initial,
                alias,
                session,
                CancellationToken.None);

            Assert.Contains("unsupported_construct", enriched.Ir.RiskCodes, StringComparer.Ordinal);
            PolicyDecision secondPass = await policyEngine.EvaluateAsync(enriched, policy, CancellationToken.None);
            Assert.Equal(PolicyOutcome.Deny, secondPass.Outcome);
            Assert.Contains("unsupported_construct", secondPass.RuleIds, StringComparer.Ordinal);
        }

        SqlParseResult ordinaryTable = parser.Parse("SELECT id FROM sav_bug019_regular_table", CancellationToken.None);
        Assert.True(ordinaryTable.Success, ordinaryTable.RedactedMessage);
        SqlAnalysis enrichedTable = await new PgCatalogResolver().EnrichAsync(
            new SqlAnalysis(ordinaryTable.Ir!, true),
            alias,
            session,
            CancellationToken.None);
        Assert.DoesNotContain("unsupported_construct", enrichedTable.Ir.RiskCodes, StringComparer.Ordinal);
        Assert.Empty(enrichedTable.Ir.UnresolvedObjects);

        SqlParseResult shadowedTable = parser.Parse(
            "SELECT id FROM sav_bug019_shadowed_table",
            CancellationToken.None);
        Assert.True(shadowedTable.Success, shadowedTable.RedactedMessage);
        SqlAnalysis enrichedShadowedTable = await new PgCatalogResolver().EnrichAsync(
            new SqlAnalysis(shadowedTable.Ir!, true),
            alias,
            session,
            CancellationToken.None);
        Assert.DoesNotContain("unsupported_construct", enrichedShadowedTable.Ir.RiskCodes, StringComparer.Ordinal);
        Assert.Empty(enrichedShadowedTable.Ir.UnresolvedObjects);

        SqlParseResult pairView = parser.Parse("SELECT id FROM sav_bug019_regular_view", CancellationToken.None);
        Assert.True(pairView.Success, pairView.RedactedMessage);
        (SqlAnalysis enrichedPairView, SqlAnalysis enrichedPairTable) = await new PgCatalogResolver().EnrichPairAsync(
            new SqlAnalysis(pairView.Ir!, true),
            new SqlAnalysis(ordinaryTable.Ir!, true),
            alias,
            session,
            CancellationToken.None);
        Assert.Contains("unsupported_construct", enrichedPairView.Ir.RiskCodes, StringComparer.Ordinal);
        Assert.DoesNotContain("unsupported_construct", enrichedPairTable.Ir.RiskCodes, StringComparer.Ordinal);
        Assert.Empty(enrichedPairView.Ir.UnresolvedObjects);
        Assert.Empty(enrichedPairTable.Ir.UnresolvedObjects);
    }

    [Fact]
    public async Task Enrich_rejects_partitioned_and_inheritance_parents_that_expand_to_descendants()
    {
        await _fixture.ExecuteAdminAsync(
            """
            CREATE TABLE public.sav_bug005_partitioned_20261001 (id int) PARTITION BY RANGE (id);
            CREATE TABLE public.sav_bug005_partition_leaf_20261001
              PARTITION OF public.sav_bug005_partitioned_20261001
              FOR VALUES FROM (0) TO (100);
            CREATE TABLE public.sav_bug005_inherit_parent_20261001 (id int);
            CREATE TABLE public.sav_bug005_inherit_child_20261001 (extra int)
              INHERITS (public.sav_bug005_inherit_parent_20261001);
            GRANT SELECT ON public.sav_bug005_partitioned_20261001,
              public.sav_bug005_partition_leaf_20261001,
              public.sav_bug005_inherit_parent_20261001,
              public.sav_bug005_inherit_child_20261001 TO sav_ro;
            """);

        await using ReadOnlySessionFactory factory = _fixture.CreateFactory();
        TargetAlias alias = _fixture.Resolve(PostgresRoFixture.RoAlias);
        await using IReadOnlySession session =
            await factory.OpenReadOnlySessionAsync(alias, CancellationToken.None);
        LibPgQuerySqlParser parser = new();
        YamlPolicyEngine policyEngine = new();
        Policy policy = new(
            id: "bug005-policy",
            version: "1",
            allowedStatementTypes: ["Select"],
            deniedTables: ["sav_bug005_partition_leaf_20261001", "sav_bug005_inherit_child_20261001"],
            deniedColumns: [],
            allowedFunctions: [],
            denyUnresolvedObjects: false,
            denyMultipleStatements: true,
            denyUpdateDeleteWithoutPredicate: true,
            maxCostBucket: "high",
            forbiddenPlanNodes: [],
            disclosure: _fixture.StrictDisclosure);

        foreach (string parent in new[]
                 {
                     "sav_bug005_partitioned_20261001",
                     "sav_bug005_inherit_parent_20261001",
                 })
        {
            SqlParseResult parsed = parser.Parse($"SELECT id FROM {parent}", CancellationToken.None);
            Assert.True(parsed.Success, parsed.RedactedMessage);

            SqlAnalysis initial = new(parsed.Ir!, true);
            PolicyDecision firstPass = await policyEngine.EvaluateAsync(initial, policy, CancellationToken.None);
            Assert.Equal(PolicyOutcome.Allow, firstPass.Outcome);

            SqlAnalysis enriched = await new PgCatalogResolver().EnrichAsync(
                initial,
                alias,
                session,
                CancellationToken.None);

            Assert.Empty(enriched.Ir.UnresolvedObjects);
            Assert.Contains("unsupported_construct", enriched.Ir.RiskCodes, StringComparer.Ordinal);
            PolicyDecision secondPass = await policyEngine.EvaluateAsync(enriched, policy, CancellationToken.None);
            Assert.Equal(PolicyOutcome.Deny, secondPass.Outcome);
            Assert.Contains("unsupported_construct", secondPass.RuleIds, StringComparer.Ordinal);
        }

        foreach (string leaf in new[]
                 {
                     "sav_bug005_partition_leaf_20261001",
                     "sav_bug005_inherit_child_20261001",
                 })
        {
            SqlParseResult parsed = parser.Parse($"SELECT id FROM {leaf}", CancellationToken.None);
            Assert.True(parsed.Success, parsed.RedactedMessage);
            SqlAnalysis enriched = await new PgCatalogResolver().EnrichAsync(
                new SqlAnalysis(parsed.Ir!, true),
                alias,
                session,
                CancellationToken.None);

            Assert.Empty(enriched.Ir.UnresolvedObjects);
            Assert.DoesNotContain("unsupported_construct", enriched.Ir.RiskCodes, StringComparer.Ordinal);
        }
    }

    [Fact]
    public async Task Enrich_keeps_unqualified_relation_outside_search_path_unresolved()
    {
        await _fixture.ExecuteAdminAsync(
            """
            CREATE SCHEMA bug007_hidden_20261001;
            CREATE TABLE bug007_hidden_20261001.sav_bug007_search_path_20261001 (id int);
            GRANT USAGE ON SCHEMA bug007_hidden_20261001 TO sav_ro;
            GRANT SELECT ON bug007_hidden_20261001.sav_bug007_search_path_20261001 TO sav_ro;
            """);

        await using ReadOnlySessionFactory factory = _fixture.CreateFactory();
        TargetAlias alias = _fixture.Resolve(PostgresRoFixture.RoAlias);
        await using IReadOnlySession session =
            await factory.OpenReadOnlySessionAsync(alias, CancellationToken.None);
        await session.ExecuteAsync(
            "SELECT pg_catalog.set_config('search_path', 'public, pg_catalog', true)",
            CancellationToken.None);

        LibPgQuerySqlParser parser = new();
        SqlParseResult unqualified = parser.Parse(
            "SELECT id FROM sav_bug007_search_path_20261001",
            CancellationToken.None);
        Assert.True(unqualified.Success, unqualified.RedactedMessage);

        SqlAnalysis hidden = await new PgCatalogResolver().EnrichAsync(
            new SqlAnalysis(unqualified.Ir!, true),
            alias,
            session,
            CancellationToken.None);

        Assert.Contains(
            "sav_bug007_search_path_20261001",
            hidden.Ir.UnresolvedObjects,
            StringComparer.Ordinal);

        SqlParseResult qualified = parser.Parse(
            "SELECT id FROM bug007_hidden_20261001.sav_bug007_search_path_20261001",
            CancellationToken.None);
        Assert.True(qualified.Success, qualified.RedactedMessage);

        SqlAnalysis explicitRelation = await new PgCatalogResolver().EnrichAsync(
            new SqlAnalysis(qualified.Ir!, true),
            alias,
            session,
            CancellationToken.None);

        Assert.Empty(explicitRelation.Ir.UnresolvedObjects);
        Assert.DoesNotContain("unsupported_construct", explicitRelation.Ir.RiskCodes, StringComparer.Ordinal);
    }

    [Fact]
    public async Task Enrich_keeps_missing_relation_unresolved()
    {
        await using ReadOnlySessionFactory factory = _fixture.CreateFactory();
        TargetAlias alias = _fixture.Resolve(PostgresRoFixture.RoAlias);
        await using IReadOnlySession session =
            await factory.OpenReadOnlySessionAsync(alias, CancellationToken.None);

        LibPgQuerySqlParser parser = new();
        SqlParseResult parse = parser.Parse("SELECT id FROM totally_missing_relation_zzz", CancellationToken.None);
        Assert.True(parse.Success);

        PgCatalogResolver resolver = new();
        SqlAnalysis enriched = await resolver.EnrichAsync(
            new SqlAnalysis(parse.Ir!, true),
            alias,
            session,
            CancellationToken.None);

        Assert.Contains(
            "totally_missing_relation_zzz",
            enriched.Ir.UnresolvedObjects,
            StringComparer.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Enrich_resolves_quoted_mixed_case_relation_exactly()
    {
        await _fixture.ExecuteAdminAsync(
            """
            DROP TABLE IF EXISTS public."CatalogMixedCaseExact";
            DROP TABLE IF EXISTS public.catalogmixedcaseexact;
            CREATE TABLE public."CatalogMixedCaseExact" (id int);
            GRANT SELECT ON public."CatalogMixedCaseExact" TO sav_ro;
            """);

        await using ReadOnlySessionFactory factory = _fixture.CreateFactory();
        TargetAlias alias = _fixture.Resolve(PostgresRoFixture.RoAlias);
        await using IReadOnlySession session =
            await factory.OpenReadOnlySessionAsync(alias, CancellationToken.None);

        SqlParseResult parse = new LibPgQuerySqlParser().Parse(
            "SELECT id FROM \"CatalogMixedCaseExact\"",
            CancellationToken.None);
        Assert.True(parse.Success, parse.RedactedMessage);
        Assert.Contains("CatalogMixedCaseExact", parse.Ir!.UnresolvedObjects, StringComparer.Ordinal);

        SqlAnalysis enriched = await new PgCatalogResolver().EnrichAsync(
            new SqlAnalysis(parse.Ir, true),
            alias,
            session,
            CancellationToken.None);

        Assert.DoesNotContain("CatalogMixedCaseExact", enriched.Ir.UnresolvedObjects, StringComparer.Ordinal);

        await _fixture.ExecuteAdminAsync(
            "DROP TABLE IF EXISTS public.\"CatalogMixedCaseExact\"; DROP TABLE IF EXISTS public.catalogmixedcaseexact;");
    }

    [Fact]
    public async Task Enrich_does_not_match_quoted_mixed_case_relation_to_lowercase_relation()
    {
        await _fixture.ExecuteAdminAsync(
            """
            DROP TABLE IF EXISTS public."CatalogMixedCaseOnlyLower";
            DROP TABLE IF EXISTS public.catalogmixedcaseonlylower;
            CREATE TABLE public.catalogmixedcaseonlylower (id int);
            GRANT SELECT ON public.catalogmixedcaseonlylower TO sav_ro;
            """);

        await using ReadOnlySessionFactory factory = _fixture.CreateFactory();
        TargetAlias alias = _fixture.Resolve(PostgresRoFixture.RoAlias);
        await using IReadOnlySession session =
            await factory.OpenReadOnlySessionAsync(alias, CancellationToken.None);

        SqlParseResult parse = new LibPgQuerySqlParser().Parse(
            "SELECT id FROM \"CatalogMixedCaseOnlyLower\"",
            CancellationToken.None);
        Assert.True(parse.Success, parse.RedactedMessage);

        SqlAnalysis enriched = await new PgCatalogResolver().EnrichAsync(
            new SqlAnalysis(parse.Ir!, true),
            alias,
            session,
            CancellationToken.None);

        Assert.Contains("CatalogMixedCaseOnlyLower", enriched.Ir.UnresolvedObjects, StringComparer.Ordinal);

        await _fixture.ExecuteAdminAsync(
            "DROP TABLE IF EXISTS public.\"CatalogMixedCaseOnlyLower\"; DROP TABLE IF EXISTS public.catalogmixedcaseonlylower;");
    }

    [Fact]
    public async Task Pair_enrichment_distinguishes_case_sensitive_relation_identities()
    {
        await _fixture.ExecuteAdminAsync(
            """
            DROP TABLE IF EXISTS public."CatalogPairCaseExisting";
            DROP TABLE IF EXISTS public.catalogpaircaseexisting;
            CREATE TABLE public.catalogpaircaseexisting (id int);
            GRANT SELECT ON public.catalogpaircaseexisting TO sav_ro;
            """);

        await using ReadOnlySessionFactory factory = _fixture.CreateFactory();
        TargetAlias alias = _fixture.Resolve(PostgresRoFixture.RoAlias);
        await using IReadOnlySession session =
            await factory.OpenReadOnlySessionAsync(alias, CancellationToken.None);

        (SqlAnalysis left, SqlAnalysis right) = await new PgCatalogResolver().EnrichPairAsync(
            CreateAnalysis("CatalogPairCaseExisting"),
            CreateAnalysis("catalogpaircaseexisting"),
            alias,
            session,
            CancellationToken.None);

        Assert.Equal(new[] { "CatalogPairCaseExisting" }, left.Ir.UnresolvedObjects);
        Assert.Empty(right.Ir.UnresolvedObjects);

        await _fixture.ExecuteAdminAsync(
            "DROP TABLE IF EXISTS public.\"CatalogPairCaseExisting\"; DROP TABLE IF EXISTS public.catalogpaircaseexisting;");
    }

    [Fact]
    public async Task Enrich_rejects_visible_non_pg_catalog_operator_before_execution()
    {
        await _fixture.ExecuteAdminAsync(
            """
            DROP OPERATOR IF EXISTS public.=== (integer, integer);
            DROP FUNCTION IF EXISTS public.sav_bug013_eq(integer, integer);
            CREATE FUNCTION public.sav_bug013_eq(integer, integer)
            RETURNS boolean
            LANGUAGE sql
            IMMUTABLE
            AS 'SELECT $1 = $2';
            CREATE OPERATOR public.=== (
              FUNCTION = public.sav_bug013_eq,
              LEFTARG = integer,
              RIGHTARG = integer
            );
            """);

        try
        {
            await using ReadOnlySessionFactory factory = _fixture.CreateFactory();
            TargetAlias alias = _fixture.Resolve(PostgresRoFixture.RoAlias);
            await using IReadOnlySession realSession =
                await factory.OpenReadOnlySessionAsync(alias, CancellationToken.None);
            CountingSession session = new(realSession);

            SqlParseResult parse = new LibPgQuerySqlParser().Parse("SELECT 1 === 1", CancellationToken.None);
            Assert.True(parse.Success, parse.RedactedMessage);
            Assert.Contains("===", parse.Ir!.Operators, StringComparer.Ordinal);

            SqlAnalysis enriched = await new PgCatalogResolver().EnrichAsync(
                new SqlAnalysis(parse.Ir, true),
                alias,
                session,
                CancellationToken.None);

            Assert.Contains("unsupported_construct", enriched.Ir.RiskCodes);
            Assert.Contains("===", enriched.Ir.Operators, StringComparer.Ordinal);
            Assert.Equal(1, session.ReaderCalls);
            Assert.Contains("pg_catalog.pg_operator_is_visible", session.SqlCalls[0], StringComparison.Ordinal);
        }
        finally
        {
            await _fixture.ExecuteAdminAsync(
                """
                DROP OPERATOR IF EXISTS public.=== (integer, integer);
                DROP FUNCTION IF EXISTS public.sav_bug013_eq(integer, integer);
                """);
        }
    }

    [Fact]
    public async Task Enrich_rejects_explicit_non_catalog_operator_without_catalog_lookup()
    {
        TargetAlias alias = _fixture.Resolve(PostgresRoFixture.RoAlias);
        FixedResultSession session = new([]);

        SqlParseResult parse = new LibPgQuerySqlParser().Parse(
            "SELECT 1 OPERATOR(public.===) 1",
            CancellationToken.None);
        Assert.True(parse.Success, parse.RedactedMessage);
        Assert.Contains("public.===", parse.Ir!.Operators, StringComparer.Ordinal);

        SqlAnalysis enriched = await new PgCatalogResolver().EnrichAsync(
            new SqlAnalysis(parse.Ir, true),
            alias,
            session,
            CancellationToken.None);

        Assert.Contains("unsupported_construct", enriched.Ir.RiskCodes);
        Assert.Equal(0, session.ReaderCalls);
    }

    [Fact]
    public async Task Enrich_accepts_explicit_pg_catalog_operator_after_conversion_lookup()
    {
        TargetAlias alias = _fixture.Resolve(PostgresRoFixture.RoAlias);
        FixedResultSession session = new([]);

        SqlParseResult parse = new LibPgQuerySqlParser().Parse(
            "SELECT 1 OPERATOR(pg_catalog.+) 1",
            CancellationToken.None);
        Assert.True(parse.Success, parse.RedactedMessage);
        Assert.Contains("pg_catalog.+", parse.Ir!.Operators, StringComparer.Ordinal);

        SqlAnalysis enriched = await new PgCatalogResolver().EnrichAsync(
            new SqlAnalysis(parse.Ir, true),
            alias,
            session,
            CancellationToken.None);

        Assert.DoesNotContain("unsupported_construct", enriched.Ir.RiskCodes);
        Assert.Equal(1, session.ReaderCalls);
    }

    [Fact]
    public async Task Enrich_accepts_unqualified_catalog_operator_without_visible_custom_definition()
    {
        await using ReadOnlySessionFactory factory = _fixture.CreateFactory();
        TargetAlias alias = _fixture.Resolve(PostgresRoFixture.RoAlias);
        await using IReadOnlySession realSession =
            await factory.OpenReadOnlySessionAsync(alias, CancellationToken.None);
        CountingSession session = new(realSession);

        SqlParseResult parse = new LibPgQuerySqlParser().Parse("SELECT 1 + 1", CancellationToken.None);
        Assert.True(parse.Success, parse.RedactedMessage);
        Assert.Contains("+", parse.Ir!.Operators, StringComparer.Ordinal);

        SqlAnalysis enriched = await new PgCatalogResolver().EnrichAsync(
            new SqlAnalysis(parse.Ir, true),
            alias,
            session,
            CancellationToken.None);

        Assert.DoesNotContain("unsupported_construct", enriched.Ir.RiskCodes);
        Assert.Equal(2, session.ReaderCalls);
        Assert.Contains("pg_catalog.pg_operator_is_visible", session.SqlCalls[0], StringComparison.Ordinal);
    }

    [Fact]
    public async Task Operator_safety_lookup_is_not_hijacked_by_search_path_operators()
    {
        await _fixture.ExecuteAdminAsync(
            """
            DROP SCHEMA IF EXISTS bug013_attack CASCADE;
            CREATE SCHEMA bug013_attack;
            GRANT USAGE ON SCHEMA bug013_attack TO sav_ro;

            CREATE FUNCTION bug013_attack.sav_bug013_name_eq(
              pg_catalog.name,
              pg_catalog.name)
            RETURNS boolean
            LANGUAGE sql
            IMMUTABLE
            AS 'SELECT false';

            CREATE FUNCTION bug013_attack.sav_bug013_int_add(integer, integer)
            RETURNS integer
            LANGUAGE sql
            IMMUTABLE
            AS 'SELECT $1';

            CREATE OPERATOR bug013_attack.= (
              FUNCTION = bug013_attack.sav_bug013_name_eq,
              LEFTARG = pg_catalog.name,
              RIGHTARG = pg_catalog.name
            );

            CREATE OPERATOR bug013_attack.+ (
              FUNCTION = bug013_attack.sav_bug013_int_add,
              LEFTARG = integer,
              RIGHTARG = integer
            );
            """);

        try
        {
            await using ReadOnlySessionFactory factory = _fixture.CreateFactory();
            TargetAlias alias = _fixture.Resolve(PostgresRoFixture.RoAlias);
            await using IReadOnlySession realSession =
                await factory.OpenReadOnlySessionAsync(alias, CancellationToken.None);

            await realSession.ExecuteAsync(
                "SELECT pg_catalog.set_config('search_path', 'bug013_attack, pg_catalog', true)",
                CancellationToken.None);

            SqlParseResult parse = new LibPgQuerySqlParser().Parse("SELECT 1 + 1", CancellationToken.None);
            Assert.True(parse.Success, parse.RedactedMessage);
            Assert.Contains("+", parse.Ir!.Operators, StringComparer.Ordinal);

            SqlAnalysis enriched = await new PgCatalogResolver().EnrichAsync(
                new SqlAnalysis(parse.Ir, true),
                alias,
                realSession,
                CancellationToken.None);

            Assert.Contains("unsupported_construct", enriched.Ir.RiskCodes);
        }
        finally
        {
            await _fixture.ExecuteAdminAsync("DROP SCHEMA IF EXISTS bug013_attack CASCADE;");
        }
    }

    [Fact]
    public void Operator_safety_sql_qualifies_its_own_operators()
    {
        string sql = PgCatalogResolver.BuildVisibleNonCatalogOperatorSql(["+"]);

        Assert.Contains("'+'::pg_catalog.name", sql, StringComparison.Ordinal);
        Assert.Contains("OPERATOR(pg_catalog.=)", sql, StringComparison.Ordinal);
        Assert.DoesNotContain("o.oprname = r.oprname", sql, StringComparison.Ordinal);
        Assert.DoesNotContain("n.nspname <>", sql, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Enrich_schema_qualified_does_not_match_different_schema()
    {
        await _fixture.ExecuteAdminAsync(
            """
            CREATE TABLE IF NOT EXISTS public.users (id int PRIMARY KEY);
            GRANT SELECT ON public.users TO sav_ro;
            """);

        await using ReadOnlySessionFactory factory = _fixture.CreateFactory();
        TargetAlias alias = _fixture.Resolve(PostgresRoFixture.RoAlias);
        await using IReadOnlySession session =
            await factory.OpenReadOnlySessionAsync(alias, CancellationToken.None);

        LibPgQuerySqlParser parser = new();
        SqlParseResult parse = parser.Parse("SELECT id FROM app.users", CancellationToken.None);
        Assert.True(parse.Success);
        Assert.Contains("app.users", parse.Ir!.UnresolvedObjects, StringComparer.OrdinalIgnoreCase);

        PgCatalogResolver resolver = new();
        SqlAnalysis enriched = await resolver.EnrichAsync(
            new SqlAnalysis(parse.Ir, true),
            alias,
            session,
            CancellationToken.None);

        Assert.Contains("app.users", enriched.Ir.UnresolvedObjects, StringComparer.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Enrich_resolves_multiple_existing_relations_with_one_relation_reader_call()
    {
        await _fixture.ExecuteAdminAsync(
            """
            CREATE TABLE IF NOT EXISTS public.catalog_batch_a (id int);
            CREATE TABLE IF NOT EXISTS public.catalog_batch_b (id int);
            GRANT SELECT ON public.catalog_batch_a, public.catalog_batch_b TO sav_ro;
            """);
        await using ReadOnlySessionFactory factory = _fixture.CreateFactory();
        TargetAlias alias = _fixture.Resolve(PostgresRoFixture.RoAlias);
        await using IReadOnlySession realSession =
            await factory.OpenReadOnlySessionAsync(alias, CancellationToken.None);
        CountingSession session = new(realSession);

        SqlAnalysis enriched = await new PgCatalogResolver().EnrichAsync(
            CreateAnalysis(
                "public.catalog_batch_a",
                "public.catalog_batch_b",
                "unsafe'; SELECT pg_sleep(10); --"),
            alias,
            session,
            CancellationToken.None);

        Assert.Equal(new[] { "unsafe'; SELECT pg_sleep(10); --" }, enriched.Ir.UnresolvedObjects);
        Assert.Equal(2, session.ReaderCalls);
        Assert.Contains("pg_catalog.pg_cast", session.SqlCalls[0], StringComparison.Ordinal);
        Assert.Contains("WITH requested", session.SqlCalls[1], StringComparison.Ordinal);
        Assert.All(session.SqlCalls, sql => Assert.DoesNotContain("unsafe'; SELECT pg_sleep(10); --", sql, StringComparison.Ordinal));
    }

    [Fact]
    public async Task Enrich_batch_keeps_only_missing_relations_unresolved()
    {
        await _fixture.ExecuteAdminAsync(
            """
            CREATE TABLE IF NOT EXISTS public.catalog_batch_existing (id int);
            CREATE TABLE IF NOT EXISTS public.users (id int);
            GRANT SELECT ON public.catalog_batch_existing, public.users TO sav_ro;
            """);
        await using ReadOnlySessionFactory factory = _fixture.CreateFactory();
        TargetAlias alias = _fixture.Resolve(PostgresRoFixture.RoAlias);
        await using IReadOnlySession realSession =
            await factory.OpenReadOnlySessionAsync(alias, CancellationToken.None);
        CountingSession session = new(realSession);

        SqlAnalysis enriched = await new PgCatalogResolver().EnrichAsync(
            CreateAnalysis("catalog_batch_existing", "catalog_batch_missing", "app.users"),
            alias,
            session,
            CancellationToken.None);

        Assert.Equal(new[] { "app.users", "catalog_batch_missing" }, enriched.Ir.UnresolvedObjects);
        Assert.Equal(2, session.ReaderCalls);
    }

    [Fact]
    public async Task Enrich_zero_safe_objects_only_reads_conversion_metadata()
    {
        await using ReadOnlySessionFactory factory = _fixture.CreateFactory();
        TargetAlias alias = _fixture.Resolve(PostgresRoFixture.RoAlias);
        await using IReadOnlySession realSession =
            await factory.OpenReadOnlySessionAsync(alias, CancellationToken.None);
        CountingSession session = new(realSession);

        SqlAnalysis enriched = await new PgCatalogResolver().EnrichAsync(
            CreateAnalysis("bad-name; DROP TABLE users"),
            alias,
            session,
            CancellationToken.None);

        Assert.Equal(new[] { "bad-name; DROP TABLE users" }, enriched.Ir.UnresolvedObjects);
        Assert.Equal(1, session.ReaderCalls);
        Assert.Contains("pg_catalog.pg_cast", Assert.Single(session.SqlCalls), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Enrich_one_safe_object_uses_direct_query_and_keeps_unsafe_object_out_of_sql()
    {
        await _fixture.ExecuteAdminAsync(
            """
            CREATE TABLE IF NOT EXISTS public.catalog_single_fast (id int);
            GRANT SELECT ON public.catalog_single_fast TO sav_ro;
            """);
        await using ReadOnlySessionFactory factory = _fixture.CreateFactory();
        TargetAlias alias = _fixture.Resolve(PostgresRoFixture.RoAlias);
        await using IReadOnlySession realSession =
            await factory.OpenReadOnlySessionAsync(alias, CancellationToken.None);
        CountingSession session = new(realSession);

        const string unsafeName = "safe'; SELECT pg_sleep(10); --";
        SqlAnalysis enriched = await new PgCatalogResolver().EnrichAsync(
            CreateAnalysis("catalog_single_fast", unsafeName),
            alias,
            session,
            CancellationToken.None);

        Assert.Equal(new[] { unsafeName }, enriched.Ir.UnresolvedObjects);
        Assert.Equal(2, session.ReaderCalls);
        Assert.All(session.SqlCalls, sql => Assert.DoesNotContain(unsafeName, sql, StringComparison.Ordinal));
        Assert.DoesNotContain("WITH requested", session.SqlCalls[1], StringComparison.Ordinal);
    }

    [Fact]
    public async Task Enrich_batch_with_unexpected_row_count_keeps_all_safe_objects_unresolved()
    {
        TargetAlias alias = _fixture.Resolve(PostgresRoFixture.RoAlias);
        FixedResultSession session = new([new OracleScalarRow(true, null, null)]);

        SqlAnalysis enriched = await new PgCatalogResolver().EnrichAsync(
            CreateAnalysis("catalog_cardinality_a", "catalog_cardinality_b"),
            alias,
            session,
            CancellationToken.None);

        Assert.Equal(
            new[] { "catalog_cardinality_a", "catalog_cardinality_b" },
            enriched.Ir.UnresolvedObjects);
        Assert.Equal(2, session.ReaderCalls);
    }

    [Fact]
    public async Task Enrich_honors_cancellation_before_catalog_query()
    {
        TargetAlias alias = _fixture.Resolve(PostgresRoFixture.RoAlias);
        FixedResultSession session = new([]);
        using CancellationTokenSource cancellation = new();
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => new PgCatalogResolver().EnrichAsync(
            CreateAnalysis("catalog_cancelled"),
            alias,
            session,
            cancellation.Token));
        Assert.Equal(0, session.ReaderCalls);
    }

    [Fact]
    public async Task Pair_enrichment_matches_sequential_results_and_deduplicates_reader_work()
    {
        await _fixture.ExecuteAdminAsync(
            "CREATE TABLE IF NOT EXISTS public.opt012_pair_a (id int); " +
            "CREATE TABLE IF NOT EXISTS public.opt012_pair_b (id int); " +
            "CREATE SCHEMA IF NOT EXISTS opt012_other; " +
            "CREATE TABLE IF NOT EXISTS opt012_other.opt012_pair_a (id int); " +
            "GRANT SELECT ON public.opt012_pair_a, public.opt012_pair_b, opt012_other.opt012_pair_a TO sav_ro;");

        await using ReadOnlySessionFactory factory = _fixture.CreateFactory();
        TargetAlias alias = _fixture.Resolve(PostgresRoFixture.RoAlias);
        await using IReadOnlySession realSession = await factory.OpenReadOnlySessionAsync(alias, CancellationToken.None);
        PgCatalogResolver resolver = new();
        (string Name, string[] Left, string[] Right)[] cases =
        [
            ("identical", ["public.opt012_pair_a"], ["public.opt012_pair_a"]),
            ("disjoint", ["public.opt012_pair_a"], ["public.opt012_pair_b"]),
            ("overlap", ["public.opt012_pair_a", "public.opt012_pair_b"], ["public.opt012_pair_b", "missing_pair"]),
            ("qualified_and_unqualified", ["public.opt012_pair_a"], ["opt012_pair_a"]),
            ("wrong_schema", ["opt012_other.opt012_pair_a"], ["missing_schema.opt012_pair_a"]),
            ("unsafe_mixed", ["public.opt012_pair_a", "bad-name"], ["public.opt012_pair_b", "also-bad"]),
            ("empty", [], []),
            ("duplicate_case_variants", ["public.opt012_pair_a", "PUBLIC.OPT012_PAIR_A"], ["public.opt012_pair_a"]),
        ];

        foreach ((string name, string[] leftNames, string[] rightNames) in cases)
        {
            SqlAnalysis left = CreateAnalysis(leftNames);
            SqlAnalysis right = CreateAnalysis(rightNames);
            CountingSession baselineSession = new(realSession);
            SqlAnalysis baselineLeft = await resolver.EnrichAsync(left, alias, baselineSession, CancellationToken.None);
            SqlAnalysis baselineRight = await resolver.EnrichAsync(right, alias, baselineSession, CancellationToken.None);

            CountingSession candidateSession = new(realSession);
            (SqlAnalysis candidateLeft, SqlAnalysis candidateRight) = await resolver.EnrichPairAsync(
                left, right, alias, candidateSession, CancellationToken.None);

            AssertAnalysisEqual(baselineLeft, candidateLeft, $"{name} left");
            AssertAnalysisEqual(baselineRight, candidateRight, $"{name} right");
            Assert.Equal(name == "empty" ? 2 : 4, baselineSession.ReaderCalls);
            int expectedCandidateReaders = name == "empty" ? 1 : 2;
            Assert.Equal(expectedCandidateReaders, candidateSession.ReaderCalls);
            Assert.DoesNotContain("missing_pair", candidateLeft.Ir.UnresolvedObjects);
            if (name == "overlap")
            {
                Assert.Equal(new[] { "missing_pair" }, candidateRight.Ir.UnresolvedObjects);
            }
        }
    }

    [Fact]
    public async Task Pair_enrichment_fails_closed_on_malformed_batch_and_honors_cancellation()
    {
        TargetAlias alias = _fixture.Resolve(PostgresRoFixture.RoAlias);
        PgCatalogResolver resolver = new();
        FixedResultSession wrongCardinality = new([new OracleScalarRow(true, null, null)]);

        (SqlAnalysis left, SqlAnalysis right) = await resolver.EnrichPairAsync(
            CreateAnalysis("pair_shape_a"),
            CreateAnalysis("pair_shape_b"),
            alias,
            wrongCardinality,
            CancellationToken.None);

        Assert.Equal(new[] { "pair_shape_a" }, left.Ir.UnresolvedObjects);
        Assert.Equal(new[] { "pair_shape_b" }, right.Ir.UnresolvedObjects);
        Assert.Equal(2, wrongCardinality.ReaderCalls);

        FixedResultSession malformedShape = new(
            [new OracleScalarRow(true, null, null), new OracleScalarRow(null, null, null)]);
        (left, right) = await resolver.EnrichPairAsync(
            CreateAnalysis("pair_shape_a"),
            CreateAnalysis("pair_shape_b"),
            alias,
            malformedShape,
            CancellationToken.None);
        Assert.Equal(new[] { "pair_shape_a" }, left.Ir.UnresolvedObjects);
        Assert.Equal(new[] { "pair_shape_b" }, right.Ir.UnresolvedObjects);
        Assert.Equal(2, malformedShape.ReaderCalls);

        FixedResultSession cancelled = new([]);
        using CancellationTokenSource cancellation = new();
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => resolver.EnrichPairAsync(
            CreateAnalysis("cancelled_pair_a"),
            CreateAnalysis("cancelled_pair_b"),
            alias,
            cancelled,
            cancellation.Token));
        Assert.Equal(0, cancelled.ReaderCalls);
    }

    [Fact]
    public void Resolver_has_no_session_factory_dependency()
    {
        ConstructorInfo[] ctors = typeof(PgCatalogResolver).GetConstructors();
        Assert.All(
            ctors,
            c => Assert.DoesNotContain(
                c.GetParameters(),
                p => typeof(IReadOnlySessionFactory).IsAssignableFrom(p.ParameterType)));
        Assert.Null(typeof(PgCatalogResolver).GetField(
            "_factory",
            BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public));
    }

    private static SqlAnalysis CreateAnalysis(params string[] unresolvedObjects)
    {
        SqlParseResult parsed = new LibPgQuerySqlParser().Parse("SELECT 1", CancellationToken.None);
        Assert.True(parsed.Success);
        SqlIr source = parsed.Ir!;
        SqlIr ir = new(
            source.Dialect,
            source.StatementTypes,
            source.TablesRead,
            source.TablesWritten,
            source.ColumnsRead,
            source.ColumnsWritten,
            source.Functions,
            source.HasMultipleStatements,
            source.HasDynamicSql,
            unresolvedObjects,
            source.RiskCodes,
            source.NormalizedSql,
            source.Fingerprint);
        return new SqlAnalysis(ir, true);
    }

    private static void AssertAnalysisEqual(SqlAnalysis expected, SqlAnalysis actual, string context)
    {
        Assert.Equal(expected.IsParsable, actual.IsParsable);
        Assert.Equal(expected.Ir.Dialect, actual.Ir.Dialect);
        Assert.Equal(expected.Ir.StatementTypes, actual.Ir.StatementTypes);
        Assert.Equal(expected.Ir.TablesRead, actual.Ir.TablesRead);
        Assert.Equal(expected.Ir.TablesWritten, actual.Ir.TablesWritten);
        Assert.Equal(expected.Ir.ColumnsRead, actual.Ir.ColumnsRead);
        Assert.Equal(expected.Ir.ColumnsWritten, actual.Ir.ColumnsWritten);
        Assert.Equal(expected.Ir.Functions, actual.Ir.Functions);
        Assert.Equal(expected.Ir.TypeReferences, actual.Ir.TypeReferences);
        Assert.Equal(expected.Ir.HasMultipleStatements, actual.Ir.HasMultipleStatements);
        Assert.Equal(expected.Ir.HasDynamicSql, actual.Ir.HasDynamicSql);
        Assert.Equal(expected.Ir.UnresolvedObjects, actual.Ir.UnresolvedObjects);
        Assert.Equal(expected.Ir.RiskCodes, actual.Ir.RiskCodes);
        Assert.Equal(expected.Ir.NormalizedSql, actual.Ir.NormalizedSql);
        Assert.Equal(expected.Ir.Fingerprint, actual.Ir.Fingerprint);
    }

    private sealed class CountingSession(IReadOnlySession inner) : IReadOnlySession
    {
        public int ReaderCalls { get; private set; }

        public List<string> SqlCalls { get; } = [];

        public Task ExecuteAsync(string sql, CancellationToken cancellationToken) =>
            inner.ExecuteAsync(sql, cancellationToken);

        public Task<IReadOnlyList<OracleScalarRow>> ExecuteReaderAsync(
            string sql,
            IReadOnlyList<OracleScalarColumn> allowedColumns,
            CancellationToken cancellationToken)
        {
            ReaderCalls++;
            SqlCalls.Add(sql);
            return inner.ExecuteReaderAsync(sql, allowedColumns, cancellationToken);
        }

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    private sealed class FixedResultSession(IReadOnlyList<OracleScalarRow> rows) : IReadOnlySession
    {
        public int ReaderCalls { get; private set; }

        public Task ExecuteAsync(string sql, CancellationToken cancellationToken) => Task.CompletedTask;

        public Task<IReadOnlyList<OracleScalarRow>> ExecuteReaderAsync(
            string sql,
            IReadOnlyList<OracleScalarColumn> allowedColumns,
            CancellationToken cancellationToken)
        {
            ReaderCalls++;
            // These tests supply malformed relation results, independently of the conversion gate.
            return Task.FromResult(sql.Contains("trusted_routines AS", StringComparison.Ordinal)
                ? (IReadOnlyList<OracleScalarRow>)[new OracleScalarRow(true, null, null)]
                : rows);
        }

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}
