using Sav.Application.Analyze;

namespace Sav.Application.Tests;

public sealed class ScaffoldSmokeTests
{
    [Fact]
    public void Application_assembly_name_is_Sav_Application()
    {
        Assert.Equal("Sav.Application", typeof(AnalyzeSqlUseCase).Assembly.GetName().Name);
    }
}
