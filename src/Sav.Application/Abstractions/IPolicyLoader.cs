using Sav.Domain.Policies;

namespace Sav.Application.Abstractions;

public interface IPolicyLoader
{
    Task<Policy> LoadAsync(string path, CancellationToken cancellationToken);
}
