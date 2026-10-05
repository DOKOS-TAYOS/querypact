using Sav.Application.Abstractions;
using Sav.Domain.Analysis;
using Sav.Domain.Decisions;
using Sav.Domain.Policies;
using Sav.Infrastructure.Config.Policies;
using Sav.Infrastructure.Postgres.Catalog;
using Sav.Infrastructure.Postgres.Parsing;
using Sav.Infrastructure.Postgres.Targets;
using Sav.Infrastructure.Postgres.Tests.Fixtures;

namespace Sav.Infrastructure.Postgres.Tests.Catalog;

[Collection(nameof(PostgresRoCollection))]
public sealed class CatalogFunctionTests
{
    private readonly PostgresRoFixture _fixture;

    public CatalogFunctionTests(PostgresRoFixture fixture)
    {
        _fixture = fixture;
    }

    [Fact]
    public async Task Case_distinct_existing_custom_functions_remain_distinct_after_catalog_validation()
    {
        await _fixture.ExecuteAdminAsync(
            """
            CREATE SCHEMA IF NOT EXISTS sav_scope;
            CREATE SCHEMA IF NOT EXISTS "SAV_SCOPE";
            CREATE OR REPLACE FUNCTION sav_scope.sav_safe_fn() RETURNS integer
                LANGUAGE sql IMMUTABLE AS 'SELECT 1';
            CREATE OR REPLACE FUNCTION sav_scope."SAV_SAFE_FN"() RETURNS integer
                LANGUAGE sql IMMUTABLE AS 'SELECT 2';
            CREATE OR REPLACE FUNCTION "SAV_SCOPE".sav_safe_fn() RETURNS integer
                LANGUAGE sql IMMUTABLE AS 'SELECT 3';
            GRANT USAGE ON SCHEMA sav_scope, "SAV_SCOPE" TO sav_ro;
            GRANT EXECUTE ON FUNCTION sav_scope.sav_safe_fn(), sav_scope."SAV_SAFE_FN"(),
                "SAV_SCOPE".sav_safe_fn() TO sav_ro;
            """);

        await using ReadOnlySessionFactory factory = _fixture.CreateFactory();
        var alias = _fixture.Resolve(PostgresRoFixture.RoAlias);
        await using var session = await factory.OpenReadOnlySessionAsync(alias, CancellationToken.None);
        Policy policy = new("function-case-policy", "1", ["Select"], [], [], ["sav_scope.sav_safe_fn"],
            false, true, true, "high", [], _fixture.StrictDisclosure);
        YamlPolicyEngine engine = new();
        PgCatalogResolver catalog = new();
        (string Sql, PolicyOutcome Expected, int Count)[] cases =
        [
            ("SELECT sav_scope.sav_safe_fn()", PolicyOutcome.Allow, 1),
            ("SELECT sav_scope.\"SAV_SAFE_FN\"()", PolicyOutcome.Deny, 1),
            ("SELECT \"SAV_SCOPE\".sav_safe_fn()", PolicyOutcome.Deny, 1),
            ("SELECT sav_scope.sav_safe_fn(), sav_scope.\"SAV_SAFE_FN\"()", PolicyOutcome.Deny, 2),
        ];
        foreach (var item in cases)
        {
            SqlParseResult parsed = new LibPgQuerySqlParser().Parse(item.Sql, CancellationToken.None);
            Assert.True(parsed.Success, parsed.RedactedMessage);
            SqlAnalysis initial = new(parsed.Ir!, true);
            Assert.Equal(item.Expected, (await engine.EvaluateAsync(initial, policy, CancellationToken.None)).Outcome);
            // Exercise catalog metadata explicitly even for calls the first policy pass denies.
            // The proposed function calls are never executed.
            SqlAnalysis enriched = await catalog.EnrichAsync(initial, alias, session, CancellationToken.None);
            Assert.Empty(enriched.Ir.RiskCodes);
            Assert.Equal(item.Count, enriched.Ir.Functions.Count);
            Assert.Equal(initial.Ir.Functions, enriched.Ir.Functions);
            Assert.Equal(initial.Ir.FunctionReferences, enriched.Ir.FunctionReferences);
            PolicyDecision decision = await engine.EvaluateAsync(enriched, policy, CancellationToken.None);
            Assert.Equal(item.Expected, decision.Outcome);
            Assert.Equal(item.Expected == PolicyOutcome.Deny ? ["unknown_function"] : Array.Empty<string>(), decision.RuleIds);
        }
    }

    [Fact]
    public async Task Unqualified_visible_custom_overload_is_rejected()
    {
        await _fixture.ExecuteAdminAsync(
            """
            CREATE SCHEMA sav_fn_guard_20261001;
            CREATE FUNCTION sav_fn_guard_20261001.length(integer)
            RETURNS integer
            LANGUAGE sql
            IMMUTABLE
            AS 'SELECT $1';
            GRANT USAGE ON SCHEMA sav_fn_guard_20261001 TO sav_ro;
            GRANT EXECUTE ON FUNCTION sav_fn_guard_20261001.length(integer) TO sav_ro;
            """);

        await using ReadOnlySessionFactory factory = _fixture.CreateFactory();
        var alias = _fixture.Resolve(PostgresRoFixture.RoAlias);
        await using var session =
            await factory.OpenReadOnlySessionAsync(alias, CancellationToken.None);
        await session.ExecuteAsync(
            "SELECT pg_catalog.set_config('search_path', 'sav_fn_guard_20261001, pg_catalog, public', true)",
            CancellationToken.None);

        LibPgQuerySqlParser parser = new();
        SqlParseResult parsed = parser.Parse("SELECT length(1)", CancellationToken.None);
        Assert.True(parsed.Success, parsed.RedactedMessage);
        Assert.Contains("length", parsed.Ir!.Functions, StringComparer.OrdinalIgnoreCase);
        Assert.Contains("length", parsed.Ir.FunctionReferences, StringComparer.Ordinal);

        Policy policy = new(
            id: "function-resolution-policy",
            version: "1",
            allowedStatementTypes: ["Select"],
            deniedTables: [],
            deniedColumns: [],
            allowedFunctions: ["length"],
            denyUnresolvedObjects: false,
            denyMultipleStatements: true,
            denyUpdateDeleteWithoutPredicate: true,
            maxCostBucket: "high",
            forbiddenPlanNodes: [],
            disclosure: _fixture.StrictDisclosure);
        YamlPolicyEngine policyEngine = new();
        SqlAnalysis initial = new(parsed.Ir, true);

        PolicyDecision firstPass = await policyEngine.EvaluateAsync(
            initial,
            policy,
            CancellationToken.None);
        Assert.Equal(PolicyOutcome.Allow, firstPass.Outcome);

        SqlAnalysis enriched = await new PgCatalogResolver().EnrichAsync(
            initial,
            alias,
            session,
            CancellationToken.None);

        Assert.Contains("unsupported_construct", enriched.Ir.RiskCodes, StringComparer.Ordinal);
        PolicyDecision secondPass = await policyEngine.EvaluateAsync(
            enriched,
            policy,
            CancellationToken.None);
        Assert.Equal(PolicyOutcome.Deny, secondPass.Outcome);
        Assert.Contains("unsupported_construct", secondPass.RuleIds, StringComparer.Ordinal);

        SqlParseResult explicitCatalog = parser.Parse(
            "SELECT pg_catalog.length('x')",
            CancellationToken.None);
        Assert.True(explicitCatalog.Success, explicitCatalog.RedactedMessage);
        Assert.Contains(
            "pg_catalog.length",
            explicitCatalog.Ir!.FunctionReferences,
            StringComparer.Ordinal);

        SqlAnalysis explicitEnriched = await new PgCatalogResolver().EnrichAsync(
            new SqlAnalysis(explicitCatalog.Ir, true),
            alias,
            session,
            CancellationToken.None);

        Assert.DoesNotContain(
            "unsupported_construct",
            explicitEnriched.Ir.RiskCodes,
            StringComparer.Ordinal);

        SqlParseResult plain = parser.Parse("SELECT 1", CancellationToken.None);
        Assert.True(plain.Success, plain.RedactedMessage);

        (SqlAnalysis pairLeft, SqlAnalysis pairRight) = await new PgCatalogResolver().EnrichPairAsync(
            initial,
            new SqlAnalysis(plain.Ir!, true),
            alias,
            session,
            CancellationToken.None);

        Assert.Contains("unsupported_construct", pairLeft.Ir.RiskCodes, StringComparer.Ordinal);
        Assert.Contains("unsupported_construct", pairRight.Ir.RiskCodes, StringComparer.Ordinal);
    }

}
