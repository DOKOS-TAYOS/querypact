using Sav.Domain.Errors;
using Sav.Domain.Targets;
using Sav.Infrastructure.Postgres.Targets;
using Sav.Infrastructure.Postgres.Tests.Fixtures;

namespace Sav.Security.Tests.Surface;

public sealed class ReadOnlyCanaryRollbackFailurePanicTests
{
    [Fact]
    public async Task Unconfirmed_rollback_marks_alias_unsafe_and_disposes_pool()
    {
        await using PostgresRoFixture fixture = new();
        await fixture.InitializeAsync();

        bool poolDisposed = false;
        UnsafeAliasRegistry registry = new();
        ReadOnlySessionFactory? factory = null;
        ReadOnlySessionGuard panicGuard = new(
            fixture.Redactor,
            fixture.StrictDisclosure,
            registry,
            canaryOverride: async (_, _, _) => CanaryInsertResult.Succeeded,
            rollbackOverride: (_, _) => throw new InvalidOperationException("rollback failed"),
            applyReadOnlyTransaction: true,
            onAliasPanic: alias =>
            {
                poolDisposed = true;
                factory!.DisposePoolWithoutReuse(alias);
            });

        factory = new ReadOnlySessionFactory(
            new AliasConnectionFactory(fixture.Binding),
            panicGuard,
            fixture.Redactor,
            new ReadOnlySessionOptions { Disclosure = fixture.StrictDisclosure },
            registry);

        await using ReadOnlySessionFactory panicFactory = factory;

        TargetAlias alias = fixture.Resolve(PostgresRoFixture.RoAlias);
        SavException ex = await Assert.ThrowsAsync<SavException>(
            () => panicFactory.OpenReadOnlySessionAsync(alias, CancellationToken.None));

        Assert.Equal(SavErrorCode.RoCanaryRollbackUnconfirmed, ex.Code);
        Assert.True(registry.IsUnsafe(alias.Alias));
        Assert.True(poolDisposed);

        SavException again = await Assert.ThrowsAsync<SavException>(
            () => panicFactory.OpenReadOnlySessionAsync(alias, CancellationToken.None));
        Assert.Equal(SavErrorCode.UnsafeWriteSuspected, again.Code);
    }
}
