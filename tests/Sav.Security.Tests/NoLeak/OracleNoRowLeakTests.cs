using Sav.Application.Abstractions;
using Sav.Domain.Contracts;
using Sav.Domain.Decisions;
using Sav.Domain.Execution;
using Sav.Domain.Properties;
using Sav.Infrastructure.Postgres.Oracle;
using Sav.Infrastructure.Postgres.Targets;
using Sav.Infrastructure.Postgres.Tests.Fixtures;

namespace Sav.Security.Tests.NoLeak;

[Collection(nameof(PostgresRoCollection))]
public sealed class OracleNoRowLeakTests
{
    private const string Canary = "CANARY_LITERAL_do_not_egress@example.invalid";

    private readonly PostgresRoFixture _fixture;

    public OracleNoRowLeakTests(PostgresRoFixture fixture)
    {
        _fixture = fixture;
    }

    [Fact]
    public async Task Wrapped_query_succeeds_template_materializes_only_count_scalar_v()
    {
        await _fixture.ExecuteAdminAsync(
            $"""
            CREATE TABLE IF NOT EXISTS public.oracle_leak_rows (
              id int PRIMARY KEY,
              secret text NOT NULL
            );
            TRUNCATE public.oracle_leak_rows;
            INSERT INTO public.oracle_leak_rows(id, secret) VALUES (1, '{Canary}');
            GRANT SELECT ON public.oracle_leak_rows TO sav_ro;
            """);

        const string agent = "SELECT id, secret FROM oracle_leak_rows";
        var ir = OracleTestIr.Create(
            columnsRead: ["id", "secret"],
            tablesRead: ["oracle_leak_rows"],
            agentSql: agent);

        string wrapped = OracleSqlBoundary.BuildWrappedCommand(
            OracleSqlTemplateKind.QuerySucceedsExists,
            ir,
            agent,
            policyAllowedFunctions: []);

        await using ReadOnlySessionFactory factory = _fixture.CreateFactory();
        await using IReadOnlySession session =
            await factory.OpenReadOnlySessionAsync(_fixture.Resolve(PostgresRoFixture.RoAlias), CancellationToken.None);

        IReadOnlyList<OracleScalarRow> rows = await session.ExecuteReaderAsync(
            wrapped,
            [OracleSqlTemplate.LongVColumn],
            CancellationToken.None);

        Assert.Single(rows);
        Assert.Null(rows[0].BoolV);
        Assert.Equal(1, rows[0].LongV);
        Assert.Null(rows[0].StringV);

        string dump = string.Join('|', rows.Select(r => $"{r.BoolV}:{r.LongV}:{r.StringV}"));
        Assert.DoesNotContain(Canary, dump, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("secret", dump, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Property_oracle_results_never_contain_row_canary()
    {
        await _fixture.ExecuteAdminAsync(
            $"""
            CREATE TABLE IF NOT EXISTS public.oracle_leak_rows2 (
              id int PRIMARY KEY,
              secret text NOT NULL
            );
            TRUNCATE public.oracle_leak_rows2;
            INSERT INTO public.oracle_leak_rows2(id, secret) VALUES (1, '{Canary}');
            GRANT SELECT ON public.oracle_leak_rows2 TO sav_ro;
            """);

        const string agent = "SELECT id, secret FROM oracle_leak_rows2";
        var ir = OracleTestIr.Create(
            columnsRead: ["id", "secret"],
            tablesRead: ["oracle_leak_rows2"],
            agentSql: agent);

        await using ReadOnlySessionFactory factory = _fixture.CreateFactory();
        await using IReadOnlySession session =
            await factory.OpenReadOnlySessionAsync(_fixture.Resolve(PostgresRoFixture.RoAlias), CancellationToken.None);

        PropertyOracle oracle = new(_fixture.Redactor);
        PropertyEvaluationRequest request = new(
            ExecutionEnvironment.RealReadOnlyAlias,
            ir,
            [new QuerySucceedsSpec(), new EmptyResultSpec()],
            agent,
            null,
            null,
            _fixture.Resolve(PostgresRoFixture.RoAlias),
            session,
            null,
            null,
            _fixture.StrictDisclosure);

        IReadOnlyList<PropertyResult> results =
            await oracle.EvaluateAsync(request, CancellationToken.None);

        Assert.Equal(2, results.Count);
        foreach (PropertyResult result in results)
        {
            Assert.DoesNotContain(Canary, result.Name, StringComparison.OrdinalIgnoreCase);
            if (result.RedactedDetail is not null)
            {
                Assert.DoesNotContain(Canary, result.RedactedDetail, StringComparison.OrdinalIgnoreCase);
            }
        }

        PropertyResult succeeds = Assert.Single(results, r => r.Name == "query_succeeds");
        PropertyResult empty = Assert.Single(results, r => r.Name == "empty_result");
        Assert.Equal(PropertyStatus.Pass, succeeds.Status);
        Assert.Equal(PropertyStatus.Fail, empty.Status);
        Assert.Equal("empty_expected_rows", empty.RedactedDetail);
    }

    [Fact]
    public void Template_wrap_never_exposes_open_row_shape()
    {
        Assert.Equal("v", OracleSqlTemplate.BoolVColumn.Name);
        Assert.Equal(OracleScalarKind.BoolV, OracleSqlTemplate.BoolVColumn.Kind);
        Assert.DoesNotContain("object", typeof(OracleScalarRow).FullName, StringComparison.OrdinalIgnoreCase);
    }
}
