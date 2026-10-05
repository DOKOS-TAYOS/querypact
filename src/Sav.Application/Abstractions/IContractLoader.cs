using Sav.Domain.Contracts;

namespace Sav.Application.Abstractions;

public interface IContractLoader
{
    Task<Contract> LoadAsync(string path, CancellationToken cancellationToken);
}
