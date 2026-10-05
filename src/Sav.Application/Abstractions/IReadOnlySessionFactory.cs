using Sav.Domain.Targets;

namespace Sav.Application.Abstractions;

/// <summary>
/// Opens a read-only session after <c>ReadOnlySessionGuard</c> (DML canary) succeeds.
/// Returns typed <see cref="IReadOnlySession"/> (not bare <see cref="IAsyncDisposable"/>).
/// </summary>
public interface IReadOnlySessionFactory
{
    Task<IReadOnlySession> OpenReadOnlySessionAsync(
        TargetAlias target,
        CancellationToken cancellationToken);
}
