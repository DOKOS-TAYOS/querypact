using Sav.Infrastructure.Storage.Attestations;

namespace Sav.Infrastructure.Storage.Tests;

public sealed class ScaffoldSmokeTests
{
    [Fact]
    public void Storage_assembly_name_is_Sav_Infrastructure_Storage()
    {
        Assert.Equal(
            "Sav.Infrastructure.Storage",
            typeof(AttestationHmac).Assembly.GetName().Name);
    }
}
