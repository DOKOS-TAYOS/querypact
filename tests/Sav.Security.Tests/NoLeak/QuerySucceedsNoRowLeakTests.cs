using Sav.Application.Abstractions;
using Sav.Domain.Contracts;
using Sav.Domain.Decisions;
using Sav.Domain.Errors;
using Sav.Domain.Execution;
using Sav.Domain.Properties;
using Sav.Infrastructure.Postgres.Oracle;
using Sav.Infrastructure.Postgres.Redaction;
using Sav.Infrastructure.Postgres.Targets;
using Sav.Infrastructure.Postgres.Tests.Fixtures;

namespace Sav.Security.Tests.NoLeak;

[Collection(nameof(PostgresRoCollection))]
public sealed class QuerySucceedsNoRowLeakTests
{
    private const string Canary = "CANARY_LITERAL_do_not_egress@example.invalid";

    private readonly PostgresRoFixture _fixture;

    public QuerySucceedsNoRowLeakTests(PostgresRoFixture fixture)
    {
        _fixture = fixture;
    }

    [Fact]
    public async Task Exists_scalar_path_never_leaks_row_payloads()
    {
        await _fixture.ExecuteAdminAsync(
            $"""
            CREATE TABLE IF NOT EXISTS public.qs_leak (
              id int PRIMARY KEY,
              secret text NOT NULL
            );
            TRUNCATE public.qs_leak;
            INSERT INTO public.qs_leak(id, secret) VALUES (1, '{Canary}');
            GRANT SELECT ON public.qs_leak TO sav_ro;
            """);

        const string agent = "SELECT id, secret FROM qs_leak";
        await using ReadOnlySessionFactory factory = _fixture.CreateFactory();
        await using IReadOnlySession session =
            await factory.OpenReadOnlySessionAsync(_fixture.Resolve(PostgresRoFixture.RoAlias), CancellationToken.None);

        PropertyOracle oracle = new(_fixture.Redactor);
        IReadOnlyList<PropertyResult> results = await oracle.EvaluateAsync(
            new PropertyEvaluationRequest(
                ExecutionEnvironment.RealReadOnlyAlias,
                OracleTestIr.Create(
                    columnsRead: ["id", "secret"],
                    tablesRead: ["qs_leak"],
                    agentSql: agent),
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
        Assert.DoesNotContain(Canary, result.ToString(), StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("secret", result.ToString(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Raise_exception_canary_redacted_to_query_failed()
    {
        await _fixture.ExecuteAdminAsync(
            $"""
            CREATE OR REPLACE FUNCTION public.sav_qs_raise_canary()
            RETURNS integer
            LANGUAGE plpgsql
            AS $$
            BEGIN
              RAISE EXCEPTION '%', '{Canary}';
            END;
            $$;
            GRANT EXECUTE ON FUNCTION public.sav_qs_raise_canary() TO sav_ro;
            """);

        const string agent = "SELECT sav_qs_raise_canary() AS v";
        await using ReadOnlySessionFactory factory = _fixture.CreateFactory();
        await using IReadOnlySession session =
            await factory.OpenReadOnlySessionAsync(_fixture.Resolve(PostgresRoFixture.RoAlias), CancellationToken.None);

        PropertyOracle oracle = new(_fixture.Redactor, allowedFunctions: ["sav_qs_raise_canary"]);
        IReadOnlyList<PropertyResult> results = await oracle.EvaluateAsync(
            new PropertyEvaluationRequest(
                ExecutionEnvironment.RealReadOnlyAlias,
                OracleTestIr.Create(
                    columnsRead: ["v"],
                    functions: ["sav_qs_raise_canary"],
                    agentSql: agent),
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
        Assert.True(result.Status is PropertyStatus.Fail or PropertyStatus.Error);
        Assert.Equal(SavErrorCode.QueryFailed, result.RedactedDetail);
        Assert.DoesNotContain(Canary, result.ToString(), StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(Canary, result.RedactedDetail ?? string.Empty, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Notice_canary_stripped_by_oracle_egress_redactor()
    {
        string raw = $"NOTICE: {Canary}\nDETAIL: ({Canary})";
        string redacted = OracleSqlBoundary.RedactEgress(_fixture.Redactor, _fixture.StrictDisclosure, raw);
        Assert.DoesNotContain(Canary, redacted, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(MinimalStrictRedactor.RedactedToken, redacted, StringComparison.Ordinal);
    }
}
