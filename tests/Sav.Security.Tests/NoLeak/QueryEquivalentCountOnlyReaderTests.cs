using Sav.Application.Abstractions;
using Sav.Domain.Contracts;
using Sav.Domain.Decisions;
using Sav.Domain.Errors;
using Sav.Domain.Execution;
using Sav.Domain.Properties;
using Sav.Infrastructure.Postgres.Oracle;
using Sav.Infrastructure.Postgres.Targets;
using Sav.Infrastructure.Postgres.Tests.Fixtures;

namespace Sav.Security.Tests.NoLeak;

[Collection(nameof(PostgresRoCollection))]
public sealed class QueryEquivalentCountOnlyReaderTests
{
    private const string Canary = "CANARY_EQ_do_not_egress@example.invalid";

    private readonly PostgresRoFixture _fixture;

    public QueryEquivalentCountOnlyReaderTests(PostgresRoFixture fixture)
    {
        _fixture = fixture;
    }

    [Fact]
    public async Task Fail_path_never_leaks_row_payload_or_diff_count()
    {
        await _fixture.ExecuteAdminAsync(
            $"""
            CREATE TABLE IF NOT EXISTS public.eq_leak (
              id int PRIMARY KEY,
              payload text NOT NULL
            );
            TRUNCATE public.eq_leak;
            INSERT INTO public.eq_leak(id, payload) VALUES
              (1, '{Canary}'),
              (2, '{Canary}');
            GRANT SELECT ON public.eq_leak TO sav_ro;
            """);

        const string left = "SELECT payload FROM eq_leak";
        const string right = "SELECT payload FROM eq_leak WHERE id = 1";

        await using ReadOnlySessionFactory factory = _fixture.CreateFactory();
        await using IReadOnlySession session =
            await factory.OpenReadOnlySessionAsync(_fixture.Resolve(PostgresRoFixture.RoAlias), CancellationToken.None);

        PropertyOracle oracle = new(_fixture.Redactor);
        IReadOnlyList<PropertyResult> results = await oracle.EvaluateAsync(
            new PropertyEvaluationRequest(
                ExecutionEnvironment.RealReadOnlyAlias,
                OracleTestIr.Create(
                    columnsRead: ["payload"],
                    tablesRead: ["eq_leak"],
                    agentSql: left),
                [new QueryEquivalentSpec()],
                null,
                left,
                right,
                _fixture.Resolve(PostgresRoFixture.RoAlias),
                session,
                null,
                null,
                _fixture.StrictDisclosure,
                rightIr: OracleTestIr.Create(
                    columnsRead: ["payload"],
                    tablesRead: ["eq_leak"],
                    agentSql: right)),
            CancellationToken.None);

        PropertyResult result = Assert.Single(results);
        Assert.Equal(PropertyStatus.Fail, result.Status);
        Assert.Equal(SavErrorCode.NotEquivalent, result.RedactedDetail);
        Assert.DoesNotContain(Canary, result.ToString(), StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("1", result.RedactedDetail!, StringComparison.Ordinal);
        Assert.DoesNotContain("2", result.RedactedDetail!, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Wrapped_except_all_materializes_only_long_scalar_v()
    {
        await _fixture.ExecuteAdminAsync(
            """
            CREATE TABLE IF NOT EXISTS public.eq_count_shape (
              id int PRIMARY KEY
            );
            TRUNCATE public.eq_count_shape;
            INSERT INTO public.eq_count_shape(id) VALUES (1), (2);
            GRANT SELECT ON public.eq_count_shape TO sav_ro;
            """);

        const string left = "SELECT id FROM eq_count_shape WHERE id = 1";
        const string right = "SELECT id FROM eq_count_shape WHERE id = 2";
        string wrapped = OracleSqlTemplate.WrapExceptAll(
            OracleSqlTemplateKind.QueryEquivalentExceptLeft,
            left,
            right);

        await using ReadOnlySessionFactory factory = _fixture.CreateFactory();
        await using IReadOnlySession session =
            await factory.OpenReadOnlySessionAsync(_fixture.Resolve(PostgresRoFixture.RoAlias), CancellationToken.None);

        IReadOnlyList<OracleScalarRow> rows = await session.ExecuteReaderAsync(
            wrapped,
            [OracleSqlTemplate.LongVColumn],
            CancellationToken.None);

        OracleScalarRow row = Assert.Single(rows);
        Assert.Null(row.BoolV);
        Assert.Null(row.StringV);
        Assert.NotNull(row.LongV);
        Assert.True(row.LongV >= 1);
    }
}
