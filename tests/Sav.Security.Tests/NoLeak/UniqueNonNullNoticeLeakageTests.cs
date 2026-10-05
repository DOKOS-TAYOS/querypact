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
public sealed class UniqueNonNullNoticeLeakageTests
{
    private const string Canary = "CANARY_LITERAL_do_not_egress@example.invalid";

    private readonly PostgresRoFixture _fixture;

    public UniqueNonNullNoticeLeakageTests(PostgresRoFixture fixture)
    {
        _fixture = fixture;
    }

    [Fact]
    public async Task Raise_exception_canary_redacted_on_unique_path()
    {
        await _fixture.ExecuteAdminAsync(
            $"""
            CREATE OR REPLACE FUNCTION public.sav_uniq_raise_canary()
            RETURNS text
            LANGUAGE plpgsql
            AS $$
            BEGIN
              RAISE EXCEPTION '%', '{Canary}';
            END;
            $$;
            GRANT EXECUTE ON FUNCTION public.sav_uniq_raise_canary() TO sav_ro;
            """);

        const string agent = "SELECT sav_uniq_raise_canary() AS code";
        await using ReadOnlySessionFactory factory = _fixture.CreateFactory();
        await using IReadOnlySession session =
            await factory.OpenReadOnlySessionAsync(_fixture.Resolve(PostgresRoFixture.RoAlias), CancellationToken.None);

        PropertyOracle oracle = new(_fixture.Redactor, allowedFunctions: ["sav_uniq_raise_canary"]);
        IReadOnlyList<PropertyResult> results = await oracle.EvaluateAsync(
            new PropertyEvaluationRequest(
                ExecutionEnvironment.RealReadOnlyAlias,
                OracleTestIr.Create(
                    columnsRead: ["code"],
                    functions: ["sav_uniq_raise_canary"],
                    agentSql: agent),
                [new UniqueSpec("code")],
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
    }

    [Fact]
    public void Notice_canary_stripped_by_egress_redactor()
    {
        string raw = $"NOTICE: {Canary}\nDETAIL: null_count=2";
        string redacted = OracleSqlBoundary.RedactEgress(
            new MinimalStrictRedactor(),
            _fixture.StrictDisclosure,
            raw);
        Assert.DoesNotContain(Canary, redacted, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(MinimalStrictRedactor.RedactedToken, redacted, StringComparison.Ordinal);
    }
}
