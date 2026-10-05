using Sav.Infrastructure.Config.Policies;

namespace Sav.Infrastructure.Config.Tests;

public sealed class ScaffoldSmokeTests
{
    [Fact]
    public void Config_assembly_name_is_Sav_Infrastructure_Config()
    {
        Assert.Equal(
            "Sav.Infrastructure.Config",
            typeof(YamlPolicyEngine).Assembly.GetName().Name);
    }
}
