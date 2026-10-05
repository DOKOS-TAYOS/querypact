using Microsoft.Extensions.DependencyInjection;
using Sav.Application.Abstractions;
using Sav.Host.Composition;
using Sav.Host.Configuration;

namespace Sav.Host.Tests.Composition;

public sealed class AnalyzeOnlyDoesNotResolveVerifyOrAttestationStoreTests
{
    [Fact]
    public void AnalyzeOnly_does_not_resolve_verify_get_or_store_ports()
    {
        using ServiceProvider sp = Program.BuildServiceProvider(
            DiProfile.AnalyzeOnly,
            options: new SavModeOptions { Mode = DiProfile.AnalyzeOnly, ConfigRoot = Path.GetTempPath() });

        Assert.Null(sp.GetService<IVerifyQueryUseCase>());
        Assert.Null(sp.GetService<IVerifyEquivalenceUseCase>());
        Assert.Null(sp.GetService<IVerifyMigrationUseCase>());
        Assert.Null(sp.GetService<IGetAttestationUseCase>());
        Assert.Null(sp.GetService<IAttestationStore>());
        Assert.Null(sp.GetService<IPlanProvider>());
        Assert.Null(sp.GetService<ICatalogResolver>());
        Assert.Null(sp.GetService<IPropertyOracle>());
        Assert.Null(sp.GetService<ITargetAliasResolver>());
        Assert.Null(sp.GetService<IReadOnlySessionFactory>());
        Assert.Null(sp.GetService<IAttestationMac>());
        Assert.Null(sp.GetService<ISchemaFingerprintGuard>());
    }
}
