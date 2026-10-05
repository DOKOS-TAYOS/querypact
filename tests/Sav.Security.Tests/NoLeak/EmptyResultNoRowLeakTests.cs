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
public sealed class EmptyResultNoRowLeakTests
{
    private const string Canary = "CANARY_LITERAL_do_not_egress@example.invalid";

    private readonly PostgresRoFixture _fixture;

    public EmptyResultNoRowLeakTests(PostgresRoFixture fixture)
    {
        _fixture = fixture;
    }

    [Fact]
    public async Task Not_exists_fail_path_never_leaks_row_payloads()
    {
        await _fixture.ExecuteAdminAsync(
            $"""
            CREATE TABLE IF NOT EXISTS public.er_leak (
              id int PRIMARY KEY,
              secret text NOT NULL
            );
            TRUNCATE public.er_leak;
            INSERT INTO public.er_leak(id, secret) VALUES (1, '{Canary}');
            GRANT SELECT ON public.er_leak TO sav_ro;
            """);

        const string agent = "SELECT id, secret FROM er_leak";
        await using ReadOnlySessionFactory factory = _fixture.CreateFactory();
        await using IReadOnlySession session =
            await factory.OpenReadOnlySessionAsync(_fixture.Resolve(PostgresRoFixture.RoAlias), CancellationToken.None);

        PropertyOracle oracle = new(_fixture.Redactor);
        IReadOnlyList<PropertyResult> results = await oracle.EvaluateAsync(
            new PropertyEvaluationRequest(
                ExecutionEnvironment.RealReadOnlyAlias,
                OracleTestIr.Create(
                    columnsRead: ["id", "secret"],
                    tablesRead: ["er_leak"],
                    agentSql: agent),
                [new EmptyResultSpec()],
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
        Assert.Equal(SavErrorCode.EmptyExpectedRows, result.RedactedDetail);
        Assert.DoesNotContain(Canary, result.ToString(), StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("1", result.RedactedDetail ?? string.Empty, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Empty_pass_path_has_no_row_payload()
    {
        const string agent = "SELECT id, payload FROM plan_items WHERE false";
        await using ReadOnlySessionFactory factory = _fixture.CreateFactory();
        await using IReadOnlySession session =
            await factory.OpenReadOnlySessionAsync(_fixture.Resolve(PostgresRoFixture.RoAlias), CancellationToken.None);

        PropertyOracle oracle = new(_fixture.Redactor);
        IReadOnlyList<PropertyResult> results = await oracle.EvaluateAsync(
            new PropertyEvaluationRequest(
                ExecutionEnvironment.RealReadOnlyAlias,
                OracleTestIr.Create(
                    columnsRead: ["id", "payload"],
                    tablesRead: ["plan_items"],
                    agentSql: agent),
                [new EmptyResultSpec()],
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
}
