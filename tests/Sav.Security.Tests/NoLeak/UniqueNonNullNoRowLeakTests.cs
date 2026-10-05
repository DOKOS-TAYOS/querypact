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
public sealed class UniqueNonNullNoRowLeakTests
{
    private const string Canary = "CANARY_LITERAL_do_not_egress@example.invalid";

    private readonly PostgresRoFixture _fixture;

    public UniqueNonNullNoRowLeakTests(PostgresRoFixture fixture)
    {
        _fixture = fixture;
    }

    [Fact]
    public async Task Unique_fail_never_leaks_row_payload_or_count()
    {
        await _fixture.ExecuteAdminAsync(
            $"""
            CREATE TABLE IF NOT EXISTS public.uniq_leak (
              id int PRIMARY KEY,
              code text NOT NULL
            );
            TRUNCATE public.uniq_leak;
            INSERT INTO public.uniq_leak(id, code) VALUES
              (1, '{Canary}'),
              (2, '{Canary}');
            GRANT SELECT ON public.uniq_leak TO sav_ro;
            """);

        PropertyResult result = await EvaluateAsync(
            "SELECT code FROM uniq_leak",
            new UniqueSpec("code"),
            ["code"],
            ["uniq_leak"]);

        Assert.Equal(PropertyStatus.Fail, result.Status);
        Assert.Equal(SavErrorCode.UniqueViolation, result.RedactedDetail);
        Assert.DoesNotContain(Canary, result.ToString(), StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("2", result.RedactedDetail!, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Non_null_fail_never_leaks_null_count()
    {
        await _fixture.ExecuteAdminAsync(
            $"""
            CREATE TABLE IF NOT EXISTS public.nn_leak (
              id int PRIMARY KEY,
              note text NULL
            );
            TRUNCATE public.nn_leak;
            INSERT INTO public.nn_leak(id, note) VALUES
              (1, '{Canary}'),
              (2, NULL),
              (3, NULL);
            GRANT SELECT ON public.nn_leak TO sav_ro;
            """);

        PropertyResult result = await EvaluateAsync(
            "SELECT note FROM nn_leak",
            new NonNullSpec("note"),
            ["note"],
            ["nn_leak"]);

        Assert.Equal(PropertyStatus.Fail, result.Status);
        Assert.Equal(SavErrorCode.NullFound, result.RedactedDetail);
        Assert.DoesNotContain(Canary, result.ToString(), StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("2", result.RedactedDetail!, StringComparison.Ordinal);
    }

    private async Task<PropertyResult> EvaluateAsync(
        string agent,
        PropertySpec spec,
        string[] columns,
        string[] tables)
    {
        await using ReadOnlySessionFactory factory = _fixture.CreateFactory();
        await using IReadOnlySession session =
            await factory.OpenReadOnlySessionAsync(_fixture.Resolve(PostgresRoFixture.RoAlias), CancellationToken.None);

        PropertyOracle oracle = new(_fixture.Redactor);
        IReadOnlyList<PropertyResult> results = await oracle.EvaluateAsync(
            new PropertyEvaluationRequest(
                ExecutionEnvironment.RealReadOnlyAlias,
                OracleTestIr.Create(
                    columnsRead: columns,
                    tablesRead: tables,
                    agentSql: agent),
                [spec],
                agent,
                null,
                null,
                _fixture.Resolve(PostgresRoFixture.RoAlias),
                session,
                null,
                null,
                _fixture.StrictDisclosure),
            CancellationToken.None);

        return Assert.Single(results);
    }
}
