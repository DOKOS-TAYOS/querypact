using Sav.Domain.Analysis;

namespace Sav.Domain.Tests;

public sealed class ScaffoldSmokeTests
{
    [Fact]
    public void Domain_assembly_name_is_Sav_Domain()
    {
        Assert.Equal("Sav.Domain", typeof(SqlIr).Assembly.GetName().Name);
    }
}
