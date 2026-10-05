using Sav.Application.Abstractions;
using Sav.Domain.Analysis;
using Sav.Domain.Targets;
using Sav.Infrastructure.Postgres.Catalog;
using Sav.Infrastructure.Postgres.Parsing;
using Sav.Infrastructure.Postgres.Targets;
using Sav.Infrastructure.Postgres.Tests.Fixtures;

namespace Sav.Infrastructure.Postgres.Tests.Catalog;

[Collection(nameof(PostgresRoCollection))]
public sealed class CatalogConversionTests(PostgresRoFixture fixture)
{
    [Theory]
    [InlineData("SELECT '7'::integer::text")]
    [InlineData("SELECT CAST(7 AS bigint)")]
    [InlineData("SELECT CAST('abc' AS varchar(8))")]
    [InlineData("SELECT 7::numeric(10,2)")]
    [InlineData("SELECT ARRAY[1,2]::bigint[]")]
    [InlineData("SELECT DATE '2026-10-02'")]
    [InlineData("SELECT 'ok'::pg_catalog.text")]
    [InlineData("SELECT '2026-10-02 12:00:00'::timestamp(3)")]
    [InlineData("SELECT 'true'::boolean")]
    [InlineData("SELECT '{}'::jsonb")]
    [InlineData("SELECT '[1,3)'::int4range")]
    [InlineData("SELECT pg_catalog.int4('7')")]
    [InlineData("SELECT 2 + 4.0")]
    [InlineData("SELECT CASE WHEN true THEN 1 ELSE 2.0 END")]
    [InlineData("SELECT 1 UNION ALL SELECT 2.0")]
    [InlineData("SELECT pg_catalog.length('abc'::text)")]
    [InlineData("SELECT id::bigint FROM public.plan_items WHERE id = 1")]
    public async Task Ordinary_explicit_and_implicit_conversions_remain_executable(string sql)
    {
        await using ReadOnlySessionFactory factory = fixture.CreateFactory();
        TargetAlias alias = fixture.Resolve(PostgresRoFixture.RoAlias);
        await using IReadOnlySession session = await factory.OpenReadOnlySessionAsync(alias, CancellationToken.None);
        SqlAnalysis analysis = Parse(sql);
        PgCatalogResolver resolver = new();
        SqlAnalysis enriched = await resolver.EnrichAsync(analysis, alias, session, CancellationToken.None);
        Assert.Empty(enriched.Ir.RiskCodes);
        Assert.Empty(enriched.Ir.UnresolvedObjects);
        Assert.Equal(analysis.Ir.TypeReferences, enriched.Ir.TypeReferences);
        (SqlAnalysis left, SqlAnalysis right) = await resolver.EnrichPairAsync(
            analysis, Parse("SELECT 1"), alias, session, CancellationToken.None);
        Assert.Empty(left.Ir.RiskCodes);
        Assert.Empty(right.Ir.RiskCodes);

        // Consume an innocuous query server-side; inspect only its aggregate row count.
        IReadOnlyList<OracleScalarRow> rows = await session.ExecuteReaderAsync(
            $"SELECT pg_catalog.count(*) AS v FROM ({sql}) AS checked_query",
            [new OracleScalarColumn("v", OracleScalarKind.LongV)], CancellationToken.None);
        Assert.True(Assert.Single(rows).LongV > 0);
    }

    [Fact]
    public async Task Custom_domains_enums_arrays_and_column_coercions_fail_closed()
    {
        await fixture.ExecuteAdminAsync(
            """
            CREATE SCHEMA bug002_types;
            CREATE DOMAIN bug002_types.positive AS integer CHECK (VALUE > 0);
            CREATE DOMAIN bug002_types.text AS pg_catalog.text;
            CREATE TYPE bug002_types.label AS ENUM ('ok');
            CREATE TABLE bug002_types.items (id bug002_types.positive, label bug002_types.label, plain integer);
            INSERT INTO bug002_types.items VALUES (1, 'ok', 7);
            CREATE FUNCTION bug002_types.get_label() RETURNS bug002_types.label
              LANGUAGE sql IMMUTABLE AS 'SELECT ''ok''::bug002_types.label';
            GRANT USAGE ON SCHEMA bug002_types TO sav_ro;
            GRANT SELECT ON bug002_types.items TO sav_ro;
            """);
        try
        {
            await using ReadOnlySessionFactory factory = fixture.CreateFactory();
            TargetAlias alias = fixture.Resolve(PostgresRoFixture.RoAlias);
            await using IReadOnlySession session = await factory.OpenReadOnlySessionAsync(alias, CancellationToken.None);
            await session.ExecuteAsync(
                "SELECT pg_catalog.set_config('search_path', 'bug002_types, pg_catalog, public', true)",
                CancellationToken.None);
            foreach (string sql in new[]
                     {
                         "SELECT 1::bug002_types.positive",
                         "SELECT 'ok'::bug002_types.label",
                         "SELECT ARRAY['ok']::bug002_types.label[]",
                         "SELECT 'ok'::label",
                         "SELECT 'ok'::text",
                         "SELECT 'ok'::bug002_types.missing",
                         "SELECT label('ok')",
                         "SELECT id + 1 FROM bug002_types.items",
                         "SELECT label::text FROM bug002_types.items",
                         "SELECT bug002_types.get_label()::text",
                         // Flattened column names do not prove relation/alias/scope binding.
                         "SELECT plain FROM bug002_types.items",
                         "SELECT i.plain FROM bug002_types.items AS i",
                         "SELECT 1 FROM bug002_types.items AS i",
                         "SELECT outer_i.plain FROM bug002_types.items AS outer_i WHERE EXISTS " +
                         "(SELECT 1 FROM bug002_types.items AS inner_i WHERE inner_i.plain = outer_i.plain)",
                     })
            {
                SqlAnalysis analysis = Parse(sql);
                PgCatalogResolver resolver = new();
                SqlAnalysis single = await resolver.EnrichAsync(analysis, alias, session, CancellationToken.None);
                Assert.Contains("unsupported_construct", single.Ir.RiskCodes);
                foreach (bool customOnLeft in new[] { true, false })
                {
                    (SqlAnalysis left, SqlAnalysis right) = await resolver.EnrichPairAsync(
                        customOnLeft ? analysis : Parse("SELECT 1"),
                        customOnLeft ? Parse("SELECT 1") : analysis,
                        alias, session, CancellationToken.None);
                    Assert.Contains("unsupported_construct", left.Ir.RiskCodes);
                    Assert.Contains("unsupported_construct", right.Ir.RiskCodes);
                }
            }

            // Explicit catalog qualification still selects the ordinary built-in type.
            SqlAnalysis qualified = await new PgCatalogResolver().EnrichAsync(
                Parse("SELECT 'ok'::pg_catalog.text"), alias, session, CancellationToken.None);
            Assert.Empty(qualified.Ir.RiskCodes);
        }
        finally
        {
            await fixture.ExecuteAdminAsync("DROP SCHEMA bug002_types CASCADE");
        }
    }

    [Theory]
    [InlineData("")]
    [InlineData("AS IMPLICIT")]
    [InlineData("AS ASSIGNMENT")]
    public async Task Added_conversion_paths_are_rejected_without_invoking_the_routine(string context)
    {
        // A harmless constant-returning routine: no writes, notices, exceptions, or external actions.
        await fixture.ExecuteAdminAsync(
            $"""
             CREATE SCHEMA bug002_cast;
             CREATE FUNCTION bug002_cast.int_text(integer) RETURNS text
               LANGUAGE sql IMMUTABLE AS 'SELECT ''ok''::text';
             CREATE CAST (integer AS text) WITH FUNCTION bug002_cast.int_text(integer) {context};
             """);
        try
        {
            await using ReadOnlySessionFactory factory = fixture.CreateFactory();
            TargetAlias alias = fixture.Resolve(PostgresRoFixture.RoAlias);
            await using IReadOnlySession session = await factory.OpenReadOnlySessionAsync(alias, CancellationToken.None);
            PgCatalogResolver resolver = new();
            foreach (string sql in new[] { "SELECT 1", "SELECT -7", "SELECT 0 AS first, 2147483647 AS last", "SELECT (7) AS value" })
            {
                SqlAnalysis analysis = Parse(sql);
                Assert.Empty((await resolver.EnrichAsync(analysis, alias, session, CancellationToken.None)).Ir.RiskCodes);
                (SqlAnalysis safeLeft, SqlAnalysis safeRight) = await resolver.EnrichPairAsync(
                    analysis, analysis, alias, session, CancellationToken.None);
                Assert.Empty(safeLeft.Ir.RiskCodes);
                Assert.Empty(safeRight.Ir.RiskCodes);
                // Only after catalog approval, consume harmless literals through the pair wrapper.
                IReadOnlyList<OracleScalarRow> rows = await session.ExecuteReaderAsync(
                    $"SELECT pg_catalog.count(*) AS v FROM (({sql}) EXCEPT ALL ({sql})) AS diff",
                    [new OracleScalarColumn("v", OracleScalarKind.LongV)], CancellationToken.None);
                Assert.Equal(0L, Assert.Single(rows).LongV);
            }

            (SqlAnalysis differentLeft, SqlAnalysis differentRight) = await resolver.EnrichPairAsync(
                Parse("SELECT 1 AS first"), Parse("SELECT 2 AS second"), alias, session, CancellationToken.None);
            Assert.Empty(differentLeft.Ir.RiskCodes);
            Assert.Empty(differentRight.Ir.RiskCodes);

            foreach (string sql in new[] { "SELECT 1::text", "SELECT CASE WHEN true THEN 1 ELSE 2.0 END" })
            {
                SqlAnalysis single = await resolver.EnrichAsync(Parse(sql), alias, session, CancellationToken.None);
                Assert.Contains("unsupported_construct", single.Ir.RiskCodes);
            }

            foreach (string sql in new[]
                     {
                         "SELECT 1.0", "SELECT 2147483648", "SELECT 'ok'", "SELECT NULL", "SELECT true",
                         "SELECT 1::integer", "SELECT 1 UNION ALL SELECT 2.0", "SELECT 1 + 2",
                         "SELECT ARRAY[1,2]", "SELECT 1 LIMIT 1", "SELECT 1 WHERE true",
                     })
            {
                SqlAnalysis analysis = Parse(sql);
                Assert.Contains("unsupported_construct", (await resolver.EnrichAsync(
                    analysis, alias, session, CancellationToken.None)).Ir.RiskCodes);
                foreach (bool unprovenOnLeft in new[] { true, false })
                {
                    (SqlAnalysis pairLeft, SqlAnalysis pairRight) = await resolver.EnrichPairAsync(
                        unprovenOnLeft ? analysis : Parse("SELECT 1"),
                        unprovenOnLeft ? Parse("SELECT 1") : analysis, alias, session, CancellationToken.None);
                    Assert.Contains("unsupported_construct", pairLeft.Ir.RiskCodes);
                    Assert.Contains("unsupported_construct", pairRight.Ir.RiskCodes);
                }
            }

            (SqlAnalysis left, SqlAnalysis right) = await resolver.EnrichPairAsync(
                Parse("SELECT 1"), Parse("SELECT 1::text"), alias, session, CancellationToken.None);
            Assert.Contains("unsupported_construct", left.Ir.RiskCodes);
            Assert.Contains("unsupported_construct", right.Ir.RiskCodes);
        }
        finally
        {
            await fixture.ExecuteAdminAsync("DROP CAST (integer AS text); DROP SCHEMA bug002_cast CASCADE");
        }
    }

    private static SqlAnalysis Parse(string sql)
    {
        SqlParseResult parsed = new LibPgQuerySqlParser().Parse(sql, CancellationToken.None);
        Assert.True(parsed.Success, parsed.RedactedMessage);
        return new SqlAnalysis(parsed.Ir!, true);
    }
}
