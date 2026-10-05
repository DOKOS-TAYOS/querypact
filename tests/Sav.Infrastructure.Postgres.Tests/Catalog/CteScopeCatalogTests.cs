using Sav.Application.Abstractions;
using Sav.Domain.Analysis;
using Sav.Infrastructure.Postgres.Catalog;
using Sav.Infrastructure.Postgres.Parsing;
using Sav.Infrastructure.Postgres.Targets;
using Sav.Infrastructure.Postgres.Tests.Fixtures;

namespace Sav.Infrastructure.Postgres.Tests.Catalog;

[Collection(nameof(PostgresRoCollection))]
public sealed class CteScopeCatalogTests(PostgresRoFixture fixture)
{
    [Fact]
    public async Task Same_named_view_in_nonrecursive_cte_is_rejected_by_catalog()
    {
        await fixture.ExecuteAdminAsync(
            """
            CREATE SCHEMA bug003_cte_scope;
            CREATE TABLE bug003_cte_scope.base (id integer);
            CREATE VIEW bug003_cte_scope.v AS SELECT id FROM bug003_cte_scope.base;
            GRANT USAGE ON SCHEMA bug003_cte_scope TO sav_ro;
            GRANT SELECT ON bug003_cte_scope.v TO sav_ro;
            """);
        try
        {
            await using ReadOnlySessionFactory factory = fixture.CreateFactory();
            var alias = fixture.Resolve(PostgresRoFixture.RoAlias);
            await using IReadOnlySession session =
                await factory.OpenReadOnlySessionAsync(alias, CancellationToken.None);
            await session.ExecuteAsync(
                "SELECT pg_catalog.set_config('search_path', 'bug003_cte_scope, public', true)",
                CancellationToken.None);

            SqlAnalysis analysis = Parse("WITH v AS (SELECT id FROM v) SELECT id FROM v");
            Assert.Equal(["v"], analysis.Ir.UnresolvedObjects);

            SqlAnalysis enriched = await new PgCatalogResolver().EnrichAsync(
                analysis, alias, session, CancellationToken.None);
            Assert.Contains("unsupported_construct", enriched.Ir.RiskCodes);

            (SqlAnalysis left, SqlAnalysis right) = await new PgCatalogResolver().EnrichPairAsync(
                analysis, Parse("SELECT 1"), alias, session, CancellationToken.None);
            Assert.Contains("unsupported_construct", left.Ir.RiskCodes);

            // A CTE-only reference must not acquire the same-named view's metadata.
            SqlAnalysis cteOnly = Parse("WITH v AS (SELECT 1 AS id) SELECT id FROM v");
            Assert.Empty(cteOnly.Ir.TablesRead);
            Assert.Empty(cteOnly.Ir.UnresolvedObjects);
            SqlAnalysis safe = await new PgCatalogResolver().EnrichAsync(
                cteOnly, alias, session, CancellationToken.None);
            Assert.DoesNotContain("unsupported_construct", safe.Ir.RiskCodes);
        }
        finally
        {
            await fixture.ExecuteAdminAsync("DROP SCHEMA bug003_cte_scope CASCADE");
        }
    }

    private static SqlAnalysis Parse(string sql)
    {
        SqlParseResult parsed = new LibPgQuerySqlParser().Parse(sql, CancellationToken.None);
        Assert.True(parsed.Success, parsed.RedactedMessage);
        return new SqlAnalysis(parsed.Ir!, true);
    }
}
