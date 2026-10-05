namespace Sav.Host.Tests;

public sealed class ScaffoldHostGuardsTests
{
    [Fact]
    public void Host_project_exists()
    {
        string root = FindRepoRoot();
        string hostProject = Path.Combine(root, "src", "Sav.Host", "Sav.Host.csproj");
        Assert.True(File.Exists(hostProject));
    }

    [Fact]
    public void Host_assembly_name_is_sav()
    {
        Assert.Equal("querypact", typeof(Sav.Host.Program).Assembly.GetName().Name);
    }

    private static string FindRepoRoot()
    {
        DirectoryInfo? dir = new(AppContext.BaseDirectory);
        while (dir is not null)
        {
            if (File.Exists(Path.Combine(dir.FullName, "QueryPact.sln")))
            {
                return dir.FullName;
            }

            dir = dir.Parent;
        }

        throw new InvalidOperationException("Could not locate QueryPact.sln from test base directory.");
    }
}
