using Sav.Application.Abstractions;
using Sav.Domain.Contracts;
using Sav.Domain.Decisions;
using Sav.Domain.Errors;
using Sav.Domain.Execution;
using Sav.Domain.Properties;
using Sav.Infrastructure.Postgres.Oracle;
using Sav.Infrastructure.Postgres.Targets;
using Sav.Infrastructure.Postgres.Tests.Fixtures;

namespace Sav.Security.Tests.Surface;

[Collection(nameof(PostgresRoCollection))]
public sealed class AffectedRowsNeverUsesRealAliasTests
{
    private readonly PostgresRoFixture _fixture;

    public AffectedRowsNeverUsesRealAliasTests(PostgresRoFixture fixture)
    {
        _fixture = fixture;
    }

    [Fact]
    public async Task Real_alias_returns_property_environment_forbidden_before_execute()
    {
        await _fixture.ExecuteAdminAsync(
            """
            CREATE TABLE IF NOT EXISTS public.aff_guard (
              id int PRIMARY KEY,
              v text NOT NULL
            );
            TRUNCATE public.aff_guard;
            INSERT INTO public.aff_guard(id, v) VALUES (1, 'keep');
            GRANT SELECT ON public.aff_guard TO sav_ro;
            """);

        await using ReadOnlySessionFactory factory = _fixture.CreateFactory();
        await using IReadOnlySession session =
            await factory.OpenReadOnlySessionAsync(_fixture.Resolve(PostgresRoFixture.RoAlias), CancellationToken.None);

        const string dml = "DELETE FROM public.aff_guard";
        PropertyOracle oracle = new(_fixture.Redactor);
        IReadOnlyList<PropertyResult> results = await oracle.EvaluateAsync(
            new PropertyEvaluationRequest(
                ExecutionEnvironment.RealReadOnlyAlias,
                OracleTestIr.Create(
                    statementTypes: ["Delete"],
                    tablesWritten: ["aff_guard"],
                    agentSql: dml),
                [new AffectedRowsSpec(0, 10)],
                dml,
                null,
                null,
                _fixture.Resolve(PostgresRoFixture.RoAlias),
                session,
                null,
                null,
                _fixture.StrictDisclosure),
            CancellationToken.None);

        PropertyResult result = Assert.Single(results);
        Assert.Equal(PropertyStatus.Error, result.Status);
        Assert.Equal(SavErrorCode.PropertyEnvironmentForbidden, result.RedactedDetail);

        await using var check = new Npgsql.NpgsqlConnection(_fixture.AdminConnectionString);
        await check.OpenAsync();
        await using var cmd = new Npgsql.NpgsqlCommand("SELECT COUNT(*)::bigint FROM public.aff_guard", check);
        long count = (long)(await cmd.ExecuteScalarAsync() ?? 0L);
        Assert.Equal(1, count);
    }
}
