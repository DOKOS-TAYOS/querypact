using Sav.Application.Abstractions;
using Sav.Domain.Errors;
using Sav.Domain.Targets;
using Sav.Infrastructure.Postgres.Targets;
using Sav.Infrastructure.Postgres.Tests.Fixtures;

namespace Sav.Infrastructure.Postgres.Tests.Targets;

[Collection(nameof(PostgresRoCollection))]
public sealed class ReadOnlyRoleEnforcementTests
{
    private readonly PostgresRoFixture _fixture;

    public ReadOnlyRoleEnforcementTests(PostgresRoFixture fixture)
    {
        _fixture = fixture;
    }

    [Fact]
    public async Task Ro_role_with_probe_opens_session_after_canary_pass()
    {
        await using ReadOnlySessionFactory factory = _fixture.CreateFactory();
        TargetAlias alias = _fixture.Resolve(PostgresRoFixture.RoAlias);

        await using IReadOnlySession session =
            await factory.OpenReadOnlySessionAsync(alias, CancellationToken.None);

        Assert.IsAssignableFrom<IReadOnlySession>(session);
        await session.ExecuteAsync("SELECT 1", CancellationToken.None);
    }

    [Fact]
    public async Task Missing_sav_ro_probe_refuses_with_ro_probe_missing()
    {
        await using ReadOnlySessionFactory factory = _fixture.CreateFactory();
        TargetAlias alias = _fixture.Resolve(PostgresRoFixture.NoProbeAlias);

        SavException ex = await Assert.ThrowsAsync<SavException>(
            () => factory.OpenReadOnlySessionAsync(alias, CancellationToken.None));

        Assert.Equal(SavErrorCode.RoProbeMissing, ex.Code);
    }

    [Fact]
    public async Task Writer_role_is_refused_by_production_guard()
    {
        // Regression for BUG-023: production must inspect the alias transaction mode as-is.
        // It must not turn a writable alias read-only before proving that the alias is safe.
        await using ReadOnlySessionFactory factory = _fixture.CreateFactory();
        TargetAlias alias = _fixture.Resolve(PostgresRoFixture.WriterAlias);

        SavException ex = await Assert.ThrowsAsync<SavException>(
            () => factory.OpenReadOnlySessionAsync(alias, CancellationToken.None));

        Assert.Equal(SavErrorCode.RoleNotReadOnly, ex.Code);
    }

    [Fact]
    public async Task Writer_permissions_with_readonly_default_do_not_change_transaction_proof()
    {
        // A read-only transaction is not a proof that the role lacks write grants.
        // The separate privilege preflight must flag this alias without weakening
        // the runtime transaction boundary.
        await using ReadOnlySessionFactory factory = _fixture.CreateFactory();
        TargetAlias alias = _fixture.Resolve(PostgresRoFixture.WriterReadOnlyAlias);

        await using IReadOnlySession session =
            await factory.OpenReadOnlySessionAsync(alias, CancellationToken.None);
        await session.ExecuteAsync("SELECT 1", CancellationToken.None);
    }

    [Fact]
    public async Task Permission_denied_on_probe_is_ro_canary_inconclusive()
    {
        // Without an effective RO transaction, missing INSERT privilege is inconclusive
        // (not a typed read-only rejection).
        ReadOnlySessionGuard guard = new(
            _fixture.Redactor,
            _fixture.StrictDisclosure,
            new UnsafeAliasRegistry(),
            canaryOverride: null,
            rollbackOverride: null,
            applyReadOnlyTransaction: false,
            onAliasPanic: null);

        await using ReadOnlySessionFactory factory = _fixture.CreateFactory(guard: guard);
        TargetAlias alias = _fixture.Resolve(PostgresRoFixture.NoInsertAlias);

        SavException ex = await Assert.ThrowsAsync<SavException>(
            () => factory.OpenReadOnlySessionAsync(alias, CancellationToken.None));

        Assert.Equal(SavErrorCode.RoCanaryInconclusive, ex.Code);
    }

    [Fact]
    public async Task Open_errors_are_redacted()
    {
        await using ReadOnlySessionFactory factory = _fixture.CreateFactory();
        TargetAlias alias = _fixture.Resolve(PostgresRoFixture.NoProbeAlias);

        SavException ex = await Assert.ThrowsAsync<SavException>(
            () => factory.OpenReadOnlySessionAsync(alias, CancellationToken.None));

        Assert.Equal(SavErrorCode.RoProbeMissing, ex.Code);
        Assert.DoesNotContain("ro_password", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("noprobe_password", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Password=", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("sav-ro-canary", ex.Message, StringComparison.OrdinalIgnoreCase);
    }
}
