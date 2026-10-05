using Sav.Application.Abstractions;
using Sav.Domain.Errors;
using Sav.Infrastructure.Postgres.Oracle;
using Sav.Infrastructure.Postgres.Targets;
using Sav.Infrastructure.Postgres.Tests.Fixtures;

namespace Sav.Infrastructure.Postgres.Tests.Sessions;

[Collection(nameof(PostgresRoCollection))]
public sealed class SessionReaderRejectsUnknownColumnsTests
{
    private readonly PostgresRoFixture _fixture;

    public SessionReaderRejectsUnknownColumnsTests(PostgresRoFixture fixture)
    {
        _fixture = fixture;
    }

    [Fact]
    public async Task Reader_rejects_columns_outside_template_allow_list()
    {
        await using ReadOnlySessionFactory factory = _fixture.CreateFactory();
        await using IReadOnlySession session =
            await factory.OpenReadOnlySessionAsync(
                _fixture.Resolve(PostgresRoFixture.RoAlias),
                CancellationToken.None);

        SavException ex = await Assert.ThrowsAsync<SavException>(
            () => session.ExecuteReaderAsync(
                "SELECT id AS v, payload AS leak FROM plan_items LIMIT 1",
                [OracleSqlTemplate.BoolVColumn],
                CancellationToken.None));

        Assert.Equal(SavErrorCode.SessionReaderColumnForbidden, ex.Code);
        Assert.DoesNotContain("row-", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("payload", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Empty_allowed_columns_fails_closed()
    {
        await using ReadOnlySessionFactory factory = _fixture.CreateFactory();
        await using IReadOnlySession session =
            await factory.OpenReadOnlySessionAsync(
                _fixture.Resolve(PostgresRoFixture.RoAlias),
                CancellationToken.None);

        SavException ex = await Assert.ThrowsAsync<SavException>(
            () => session.ExecuteReaderAsync(
                "SELECT true AS v",
                [],
                CancellationToken.None));

        Assert.Equal(SavErrorCode.SessionReaderColumnsRequired, ex.Code);
    }

    [Fact]
    public async Task Template_scalar_v_is_accepted()
    {
        await using ReadOnlySessionFactory factory = _fixture.CreateFactory();
        await using IReadOnlySession session =
            await factory.OpenReadOnlySessionAsync(
                _fixture.Resolve(PostgresRoFixture.RoAlias),
                CancellationToken.None);

        IReadOnlyList<OracleScalarRow> rows = await session.ExecuteReaderAsync(
            "SELECT EXISTS (SELECT 1 FROM plan_items WHERE id = 1) AS v",
            [OracleSqlTemplate.BoolVColumn],
            CancellationToken.None);

        Assert.Single(rows);
        Assert.True(rows[0].BoolV);
        Assert.Null(rows[0].StringV);
    }
}
