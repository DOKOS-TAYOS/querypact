using Microsoft.Extensions.DependencyInjection;
using Sav.Application.Abstractions;
using Sav.Application.Attestations;
using Sav.Host.Composition;
using Sav.Host.Configuration;
using Sav.Infrastructure.Postgres.Catalog;
using Sav.Infrastructure.Postgres.Targets;
using Sav.Infrastructure.Storage.Attestations;

namespace Sav.Host.Tests.Composition;

public sealed class HostProfileRegistrationFullTests
{
    private static readonly byte[] Key = Enumerable.Repeat((byte)0x41, 32).ToArray();

    [Fact]
    public async Task Full_registers_attestation_mac_factory_and_verify_stack()
    {
        await using ServiceProvider sp = Program.BuildServiceProvider(
            DiProfile.Full,
            options: new SavModeOptions
            {
                Mode = DiProfile.Full,
                ConfigRoot = Path.GetTempPath(),
                AttestationStoreRoot = Path.Combine(Path.GetTempPath(), "sav-attest-" + Guid.NewGuid().ToString("N")),
            },
            hmacKey: Key);

        Assert.IsType<AttestationHmac>(sp.GetRequiredService<IAttestationMac>());
        Assert.NotNull(sp.GetService<AttestationFactory>());
        Assert.NotNull(sp.GetService<IVerifyQueryUseCase>());
        Assert.NotNull(sp.GetService<IGetAttestationUseCase>());
        Assert.NotNull(sp.GetService<IAttestationStore>());
        Assert.IsType<SchemaFingerprintGuard>(sp.GetRequiredService<ISchemaFingerprintGuard>());
        Assert.IsType<ReadOnlySessionFactory>(sp.GetRequiredService<IReadOnlySessionFactory>());
        Assert.NotNull(sp.GetService<IVerifyEquivalenceUseCase>());
        Assert.NotNull(sp.GetService<IVerifyMigrationUseCase>());
    }
}
