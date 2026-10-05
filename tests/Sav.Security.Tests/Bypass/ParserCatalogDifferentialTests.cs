using System.Text.Json;
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
public sealed class ParserCatalogDifferentialTests
{
    private readonly PostgresRoFixture _fixture;

    public ParserCatalogDifferentialTests(PostgresRoFixture fixture)
    {
        _fixture = fixture;
    }

    [Fact]
    public async Task Each_differential_seed_denies_when_parser_and_catalog_disagree()
    {
        IReadOnlyList<DifferentialSeed> seeds = LoadSeeds();
        Assert.True(seeds.Count >= 5);

        await using ReadOnlySessionFactory factory = _fixture.CreateFactory();
        TargetAlias alias = _fixture.Resolve(PostgresRoFixture.RoAlias);
        LibPgQuerySqlParser parser = new();
        PgCatalogResolver catalog = new();
        YamlPolicyEngine engine = new();
        Policy policy = CreateDenyUnresolvedPolicy();

        foreach (DifferentialSeed seed in seeds)
        {
            await EnsureCatalogAsync(seed);

            await using IReadOnlySession session =
                await factory.OpenReadOnlySessionAsync(alias, CancellationToken.None);

            SqlParseResult parse = parser.Parse(seed.Sql, CancellationToken.None);
            Assert.True(parse.Success, seed.Id);
            foreach (string claim in seed.ParserClaims)
            {
                Assert.Contains(
                    claim,
                    parse.Ir!.UnresolvedObjects.Concat(parse.Ir.TablesRead).Concat(parse.Ir.TablesWritten),
                    StringComparer.OrdinalIgnoreCase);
            }

            SqlAnalysis enriched = await catalog.EnrichAsync(
                new SqlAnalysis(parse.Ir!, true),
                alias,
                session,
                CancellationToken.None);

            PolicyDecision decision = await engine.EvaluateAsync(
                enriched,
                policy,
                CancellationToken.None);

            Assert.Equal(PolicyOutcome.Deny, decision.Outcome);
            Assert.NotEqual(PolicyOutcome.Allow, decision.Outcome);
            Assert.Contains("unresolved_object", decision.RuleIds);
            Assert.NotEmpty(enriched.Ir.UnresolvedObjects);
        }
    }

    private async Task EnsureCatalogAsync(DifferentialSeed seed)
    {
        // Shared PostgresRoCollection may leave tables created by sibling tests
        // (e.g. public.users). Drop parser-claimed relations that must stay unresolved
        // for missing/different seeds before installing catalogNames.
        foreach (string claim in seed.ParserClaims)
        {
            if (!PgCatalogResolver.TryParseObjectName(claim, out string? claimSchema, out string claimRelation))
            {
                continue;
            }

            string claimSchemaName = claimSchema ?? "public";
            await _fixture.ExecuteAdminAsync(
                $"DROP TABLE IF EXISTS {claimSchemaName}.{claimRelation} CASCADE;");
        }

        foreach (string name in seed.CatalogNames)
        {
            if (!PgCatalogResolver.TryParseObjectName(name, out string? schema, out string relation))
            {
                throw new InvalidOperationException("Bad catalog name in seed: " + name);
            }

            string schemaName = schema ?? "public";
            await _fixture.ExecuteAdminAsync(
                $"""
                CREATE SCHEMA IF NOT EXISTS {schemaName};
                CREATE TABLE IF NOT EXISTS {schemaName}.{relation} (id int PRIMARY KEY);
                GRANT USAGE ON SCHEMA {schemaName} TO sav_ro;
                GRANT SELECT ON {schemaName}.{relation} TO sav_ro;
                """);
        }
    }

    private static IReadOnlyList<DifferentialSeed> LoadSeeds()
    {
        string path = Path.Combine(
            SecurityAnalyzeHarness.FindRepoRoot(),
            "tests",
            "fixtures",
            "sql",
            "parser-catalog-differential-seeds.json");
        using FileStream stream = File.OpenRead(path);
        using JsonDocument doc = JsonDocument.Parse(stream);
        List<DifferentialSeed> seeds = [];
        foreach (JsonElement item in doc.RootElement.GetProperty("cases").EnumerateArray())
        {
            seeds.Add(new DifferentialSeed(
                Id: item.GetProperty("id").GetString()!,
                Sql: item.GetProperty("sql").GetString()!,
                ParserClaims: item.GetProperty("parserClaims").EnumerateArray()
                    .Select(e => e.GetString()!)
                    .ToArray(),
                CatalogOutcome: item.GetProperty("catalogOutcome").GetString()!,
                CatalogNames: item.GetProperty("catalogNames").EnumerateArray()
                    .Select(e => e.GetString()!)
                    .ToArray()));
        }

        return seeds;
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
            denyUpdateDeleteWithoutPredicate: false,
            maxCostBucket: "high",
            forbiddenPlanNodes: [],
            disclosure: new DisclosureProfile("strict", false, false, false, false));
    }

    private sealed record DifferentialSeed(
        string Id,
        string Sql,
        IReadOnlyList<string> ParserClaims,
        string CatalogOutcome,
        IReadOnlyList<string> CatalogNames);
}
