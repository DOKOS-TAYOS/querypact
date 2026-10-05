using Sav.Application.Abstractions;
using Sav.Domain.Contracts;
using Sav.Domain.Decisions;
using Sav.Domain.Errors;
using Sav.Domain.Execution;
using Sav.Domain.Properties;
using Sav.Infrastructure.Postgres.Oracle;
using Sav.Infrastructure.Postgres.Targets;
using Sav.Infrastructure.Postgres.Tests.Fixtures;

namespace Sav.Infrastructure.Postgres.Tests.Oracle;

[Collection(nameof(PostgresRoCollection))]
public sealed class MvpAReadPropertyTests
{
    private readonly PostgresRoFixture _fixture;

    public MvpAReadPropertyTests(PostgresRoFixture fixture)
    {
        _fixture = fixture;
    }

    [Fact]
    public async Task Empty_select_both_properties_pass()
    {
        const string agent = "SELECT id, payload FROM plan_items WHERE false";
        IReadOnlyList<PropertyResult> results = await EvaluateBothAsync(agent);

        PropertyResult succeeds = Assert.Single(results, r => r.Name == "query_succeeds");
        PropertyResult empty = Assert.Single(results, r => r.Name == "empty_result");
        Assert.Equal(PropertyStatus.Pass, succeeds.Status);
        Assert.Null(succeeds.RedactedDetail);
        Assert.Equal(PropertyStatus.Pass, empty.Status);
        Assert.Null(empty.RedactedDetail);
    }

    [Fact]
    public async Task Non_empty_select_succeeds_pass_empty_fail()
    {
        const string agent = "SELECT id, payload FROM plan_items WHERE id = 1";
        IReadOnlyList<PropertyResult> results = await EvaluateBothAsync(agent);

        PropertyResult succeeds = Assert.Single(results, r => r.Name == "query_succeeds");
        PropertyResult empty = Assert.Single(results, r => r.Name == "empty_result");
        Assert.Equal(PropertyStatus.Pass, succeeds.Status);
        Assert.Equal(PropertyStatus.Fail, empty.Status);
        Assert.Equal(SavErrorCode.EmptyExpectedRows, empty.RedactedDetail);
    }

    [Fact]
    public async Task Execution_error_both_fail_or_error_with_query_failed_never_not_evaluated()
    {
        const string agent = "SELECT id FROM totally_missing_mvp_a_table_zzz";
        IReadOnlyList<PropertyResult> results = await EvaluateBothAsync(
            agent,
            columnsRead: ["id"],
            tablesRead: ["totally_missing_mvp_a_table_zzz"]);

        Assert.Equal(2, results.Count);
        Assert.All(results, r => Assert.NotEqual(PropertyStatus.NotEvaluated, r.Status));
        Assert.All(
            results,
            r => Assert.True(
                r.Status is PropertyStatus.Fail or PropertyStatus.Error,
                r.Name + " status=" + r.Status));
        Assert.All(results, r => Assert.Equal(SavErrorCode.QueryFailed, r.RedactedDetail));
    }

    [Fact]
    public async Task Query_succeeds_fails_when_projected_expression_errors_during_row_evaluation()
    {
        await _fixture.ExecuteAdminAsync(
            """
            CREATE TABLE IF NOT EXISTS public.qs_runtime_error (
              id int PRIMARY KEY
            );
            TRUNCATE public.qs_runtime_error;
            INSERT INTO public.qs_runtime_error(id) VALUES (1);
            GRANT SELECT ON public.qs_runtime_error TO sav_ro;
            """);

        const string agent = "SELECT 1 / (id - 1) AS value FROM public.qs_runtime_error";
        await using ReadOnlySessionFactory factory = _fixture.CreateFactory();
        await using IReadOnlySession session =
            await factory.OpenReadOnlySessionAsync(_fixture.Resolve(PostgresRoFixture.RoAlias), CancellationToken.None);

        PropertyOracle oracle = new(_fixture.Redactor);
        IReadOnlyList<PropertyResult> results = await oracle.EvaluateAsync(
            new PropertyEvaluationRequest(
                ExecutionEnvironment.RealReadOnlyAlias,
                CreateIr(agent, ["id"], ["qs_runtime_error"]),
                [new QuerySucceedsSpec()],
                agent,
                null,
                null,
                _fixture.Resolve(PostgresRoFixture.RoAlias),
                session,
                null,
                null,
                _fixture.StrictDisclosure),
            CancellationToken.None);

        PropertyResult result = Assert.Single(results);
        Assert.Equal(PropertyStatus.Fail, result.Status);
        Assert.Equal(SavErrorCode.QueryFailed, result.RedactedDetail);
    }

    [Fact]
    public async Task Query_succeeds_ignores_exists_boolean_when_rows_present()
    {
        const string agent = "SELECT id FROM plan_items LIMIT 5";
        await using ReadOnlySessionFactory factory = _fixture.CreateFactory();
        await using IReadOnlySession session =
            await factory.OpenReadOnlySessionAsync(_fixture.Resolve(PostgresRoFixture.RoAlias), CancellationToken.None);

        PropertyOracle oracle = new(_fixture.Redactor);
        IReadOnlyList<PropertyResult> results = await oracle.EvaluateAsync(
            new PropertyEvaluationRequest(
                ExecutionEnvironment.RealReadOnlyAlias,
                CreateIr(agent, ["id"], ["plan_items"]),
                [new QuerySucceedsSpec()],
                agent,
                null,
                null,
                _fixture.Resolve(PostgresRoFixture.RoAlias),
                session,
                null,
                null,
                _fixture.StrictDisclosure),
            CancellationToken.None);

        PropertyResult result = Assert.Single(results);
        Assert.Equal(PropertyStatus.Pass, result.Status);
        Assert.Null(result.RedactedDetail);
    }

    [Fact]
    public async Task Four_read_properties_keep_expected_status_and_order_on_real_postgres()
    {
        const string agent = "SELECT id, payload FROM public.plan_items WHERE id <= 100";
        await using ReadOnlySessionFactory factory = _fixture.CreateFactory();
        await using IReadOnlySession session =
            await factory.OpenReadOnlySessionAsync(_fixture.Resolve(PostgresRoFixture.RoAlias), CancellationToken.None);
        PropertyOracle oracle = new(_fixture.Redactor);

        IReadOnlyList<PropertyResult> results = await oracle.EvaluateAsync(
            new PropertyEvaluationRequest(
                ExecutionEnvironment.RealReadOnlyAlias,
                CreateIr(agent, ["id", "payload"], ["plan_items"]),
                [new QuerySucceedsSpec(), new EmptyResultSpec(), new UniqueSpec("id"), new NonNullSpec("payload")],
                agent,
                null,
                null,
                _fixture.Resolve(PostgresRoFixture.RoAlias),
                session,
                null,
                null,
                _fixture.StrictDisclosure),
            CancellationToken.None);

        Assert.Equal(
            [
                new PropertyResult("query_succeeds", PropertyStatus.Pass, null),
                new PropertyResult("empty_result", PropertyStatus.Fail, SavErrorCode.EmptyExpectedRows),
                new PropertyResult("unique", PropertyStatus.Pass, null),
                new PropertyResult("non_null", PropertyStatus.Pass, null),
            ],
            results);
    }

    [Fact]
    public async Task Honors_cancellation_token()
    {
        const string agent = "SELECT id FROM plan_items";
        await using ReadOnlySessionFactory factory = _fixture.CreateFactory();
        await using IReadOnlySession session =
            await factory.OpenReadOnlySessionAsync(_fixture.Resolve(PostgresRoFixture.RoAlias), CancellationToken.None);

        using CancellationTokenSource cts = new();
        await cts.CancelAsync();

        PropertyOracle oracle = new(_fixture.Redactor);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => oracle.EvaluateAsync(
                new PropertyEvaluationRequest(
                    ExecutionEnvironment.RealReadOnlyAlias,
                    CreateIr(agent, ["id"], ["plan_items"]),
                    [new QuerySucceedsSpec()],
                    agent,
                    null,
                    null,
                    _fixture.Resolve(PostgresRoFixture.RoAlias),
                    session,
                    null,
                    null,
                    _fixture.StrictDisclosure),
                cts.Token));
    }

    private async Task<IReadOnlyList<PropertyResult>> EvaluateBothAsync(
        string agent,
        string[]? columnsRead = null,
        string[]? tablesRead = null)
    {
        await using ReadOnlySessionFactory factory = _fixture.CreateFactory();
        await using IReadOnlySession session =
            await factory.OpenReadOnlySessionAsync(_fixture.Resolve(PostgresRoFixture.RoAlias), CancellationToken.None);

        PropertyOracle oracle = new(_fixture.Redactor);
        return await oracle.EvaluateAsync(
            new PropertyEvaluationRequest(
                ExecutionEnvironment.RealReadOnlyAlias,
                CreateIr(agent, columnsRead ?? ["id", "payload"], tablesRead ?? ["plan_items"]),
                [new QuerySucceedsSpec(), new EmptyResultSpec()],
                agent,
                null,
                null,
                _fixture.Resolve(PostgresRoFixture.RoAlias),
                session,
                null,
                null,
                _fixture.StrictDisclosure),
            CancellationToken.None);
    }

    private static Sav.Domain.Analysis.SqlIr CreateIr(
        string agent,
        string[] columnsRead,
        string[] tablesRead)
    {
        return new Sav.Domain.Analysis.SqlIr(
            "postgresql",
            ["Select"],
            tablesRead,
            [],
            columnsRead,
            [],
            [],
            false,
            false,
            [],
            [],
            agent,
            "mvp-a-fp");
    }
}
