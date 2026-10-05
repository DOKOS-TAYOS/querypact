using Sav.Infrastructure.Config.Paths;

namespace Sav.Infrastructure.Config.Tests;

public sealed class ConfigPathResolverTests
{
    [Theory]
    [InlineData(@"\\?\UNC\server\share\policy.yaml", @"\\server\share\policy.yaml")]
    [InlineData(@"\\?\unc\server\share\policy.yaml", @"\\server\share\policy.yaml")]
    [InlineData(@"\\?\C:\config\policy.yaml", @"C:\config\policy.yaml")]
    [InlineData(@"\\server\share\policy.yaml", @"\\server\share\policy.yaml")]
    [InlineData(@"C:\config\policy.yaml", @"C:\config\policy.yaml")]
    public void Normalizes_Windows_final_path_without_losing_UNC_root(
        string finalPath,
        string expected)
    {
        Assert.Equal(expected, ConfigPathResolver.NormalizeWindowsFinalPath(finalPath));
    }
}
