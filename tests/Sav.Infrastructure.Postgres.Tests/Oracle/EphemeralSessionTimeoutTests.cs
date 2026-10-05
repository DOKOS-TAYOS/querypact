using Sav.Application.Abstractions;
using Sav.Infrastructure.Postgres.Oracle;
using Sav.Infrastructure.Postgres.Tests.Fixtures;

namespace Sav.Infrastructure.Postgres.Tests.Oracle;

[Collection(nameof(PostgresRoCollection))]
public sealed class EphemeralSessionTimeoutTests
{
    private readonly PostgresRoFixture _fixture;

    public EphemeralSessionTimeoutTests(PostgresRoFixture fixture)
    {
        _fixture = fixture;
    }

    [Fact]
    public async Task OpenAsync_applies_statement_and_lock_timeouts()
    {
        EphemeralSessionFactory factory = new(_fixture.Redactor, _fixture.StrictDisclosure);
        await using EphemeralSession session = await factory.OpenAsync(
            _fixture.AdminConnectionString,
            CancellationToken.None);

        string statementTimeout = await ReadSettingAsync(session, "statement_timeout");
        string lockTimeout = await ReadSettingAsync(session, "lock_timeout");

        Assert.False(string.IsNullOrWhiteSpace(statementTimeout));
        Assert.False(string.IsNullOrWhiteSpace(lockTimeout));
        Assert.NotEqual("0", statementTimeout.Trim(), StringComparer.OrdinalIgnoreCase);
        Assert.NotEqual("0", lockTimeout.Trim(), StringComparer.OrdinalIgnoreCase);
    }

    private static async Task<string> ReadSettingAsync(EphemeralSession session, string setting)
    {
        IReadOnlyList<OracleScalarRow> rows = await session.ExecuteReaderAsync(
            "SELECT current_setting('" + setting + "') AS v",
            [new OracleScalarColumn("v", OracleScalarKind.StringV)],
            CancellationToken.None);
        return Assert.Single(rows).StringV ?? string.Empty;
    }
}
