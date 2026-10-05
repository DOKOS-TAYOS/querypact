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

namespace Sav.Security.Tests.Bypass;

[Collection(nameof(PostgresRoCollection))]
public sealed class DenyUnresolvedObjectTests
{
    private readonly PostgresRoFixture _fixture;

    public DenyUnresolvedObjectTests(PostgresRoFixture fixture)
    {
        _fixture = fixture;
    }

    [Fact]
    public async Task Missing_object_after_enrich_denies_with_unresolved_rule()
    {
        await using ReadOnlySessionFactory factory = _fixture.CreateFactory();
        TargetAlias alias = _fixture.Resolve(PostgresRoFixture.RoAlias);
        await using IReadOnlySession session =
            await factory.OpenReadOnlySessionAsync(alias, CancellationToken.None);

        LibPgQuerySqlParser parser = new();
        SqlParseResult parse = parser.Parse("SELECT id FROM missing_for_deny_xyz", CancellationToken.None);
        Assert.True(parse.Success);

        PgCatalogResolver catalog = new();
        SqlAnalysis enriched = await catalog.EnrichAsync(
            new SqlAnalysis(parse.Ir!, true),
            alias,
            session,
            CancellationToken.None);

        Assert.Contains(
            "missing_for_deny_xyz",
            enriched.Ir.UnresolvedObjects,
            StringComparer.OrdinalIgnoreCase);

        YamlPolicyEngine engine = new();
        PolicyDecision decision = await engine.EvaluateAsync(
            enriched,
            CreateDenyUnresolvedPolicy(),
            CancellationToken.None);

        Assert.Equal(PolicyOutcome.Deny, decision.Outcome);
        Assert.Contains("unresolved_object", decision.RuleIds);
    }

    [Fact]
    public async Task Resolved_object_after_enrich_is_not_denied_for_unresolved()
    {
        await _fixture.ExecuteAdminAsync(
            """
            CREATE TABLE IF NOT EXISTS public.resolved_users (id int PRIMARY KEY);
            GRANT SELECT ON public.resolved_users TO sav_ro;
            """);

        await using ReadOnlySessionFactory factory = _fixture.CreateFactory();
        TargetAlias alias = _fixture.Resolve(PostgresRoFixture.RoAlias);
        await using IReadOnlySession session =
            await factory.OpenReadOnlySessionAsync(alias, CancellationToken.None);

        LibPgQuerySqlParser parser = new();
        SqlParseResult parse = parser.Parse("SELECT id FROM resolved_users", CancellationToken.None);
        Assert.True(parse.Success);
        Assert.NotEmpty(parse.Ir!.UnresolvedObjects);

        PgCatalogResolver catalog = new();
        SqlAnalysis enriched = await catalog.EnrichAsync(
            new SqlAnalysis(parse.Ir, true),
            alias,
            session,
            CancellationToken.None);

        Assert.Empty(enriched.Ir.UnresolvedObjects);

        YamlPolicyEngine engine = new();
        PolicyDecision decision = await engine.EvaluateAsync(
            enriched,
            CreateDenyUnresolvedPolicy(),
            CancellationToken.None);

        Assert.DoesNotContain("unresolved_object", decision.RuleIds);
        Assert.Equal(PolicyOutcome.Allow, decision.Outcome);
    }

    private static Policy CreateDenyUnresolvedPolicy()
    {
        return new Policy(
            "deny-unresolved",
            "1",
            ["Select", "Insert", "Update", "Delete"],
            [],
            [],
            [],
            denyUnresolvedObjects: true,
            denyMultipleStatements: true,
            denyUpdateDeleteWithoutPredicate: true,
            maxCostBucket: "high",
            forbiddenPlanNodes: [],
            disclosure: new DisclosureProfile("strict", false, false, false, false));
    }
}
