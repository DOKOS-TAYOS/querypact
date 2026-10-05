namespace Sav.Security.Tests;

public sealed class ScaffoldTreeGuardsTests
{
    [Fact]
    public void Only_Sav_Host_is_the_executable_project()
    {
        string root = FindRepoRoot();
        string[] projectFiles = Directory.GetFiles(root, "*.csproj", SearchOption.AllDirectories);
        List<string> exeProjects = [];

        foreach (string path in projectFiles)
        {
            string relative = Path.GetRelativePath(root, path);
            if (relative.StartsWith("artifacts" + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) ||
                relative.StartsWith("artifacts" + Path.AltDirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) ||
                relative.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}", StringComparison.OrdinalIgnoreCase) ||
                relative.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            string text = File.ReadAllText(path);
            if (text.Contains("<OutputType>Exe</OutputType>", StringComparison.OrdinalIgnoreCase))
            {
                exeProjects.Add(Path.GetFileNameWithoutExtension(path));
            }
        }

        Assert.Equal(["Sav.Host"], exeProjects);
    }

    [Fact]
    public void Security_tests_project_does_not_reference_application_or_domain()
    {
        string root = FindRepoRoot();
        string csprojPath = Path.Combine(root, "tests", "Sav.Security.Tests", "Sav.Security.Tests.csproj");
        string text = File.ReadAllText(csprojPath);

        Assert.DoesNotContain("Sav.Application.csproj", text, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Sav.Domain.csproj", text, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Sole_exe_guard_method_exists_only_once_across_tests()
    {
        string root = FindRepoRoot();
        string[] testFiles = Directory.GetFiles(Path.Combine(root, "tests"), "*.cs", SearchOption.AllDirectories);
        string[] methodNames =
        [
            "Only_Sav_Host_is_the_executable_project",
            "Only_Sav_Host_is_executable",
        ];
        int matches = 0;

        foreach (string path in testFiles)
        {
            string text = File.ReadAllText(path);
            foreach (string methodName in methodNames)
            {
                if (System.Text.RegularExpressions.Regex.IsMatch(
                        text,
                        $@"void\s+{System.Text.RegularExpressions.Regex.Escape(methodName)}\s*\("))
                {
                    matches++;
                }
            }
        }

        Assert.Equal(1, matches);
    }

    [Fact]
    public void M001_scaffold_paths_are_tracked_by_git()
    {
        string solutionRoot = FindRepoRoot();
        string gitRoot = FindGitRoot(solutionRoot);
        string prefix = Path.GetRelativePath(gitRoot, solutionRoot).Replace('\\', '/');
        if (prefix is "." or "")
        {
            prefix = string.Empty;
        }
        else
        {
            prefix += "/";
        }

        string[] required =
        [
            "src/Sav.Host/Sav.Host.csproj",
            "src/Sav.Host/Program.cs",
            "Directory.Build.props",
            "Directory.Packages.props",
            "QueryPact.sln",
            "global.json",
            ".editorconfig",
            ".gitignore",
            "build/NativeLibPgQuery.props",
            "tests/Sav.Host.Tests/VersionCommandTests.cs",
        ];

        foreach (string relative in required)
        {
            string gitPath = prefix + relative;
            Assert.True(
                IsGitTracked(gitRoot, gitPath),
                $"Expected git-tracked path: {gitPath}");
        }
    }

    [Fact]
    public void Git_diff_check_is_clean_for_tracked_and_staged_changes()
    {
        string solutionRoot = FindRepoRoot();
        string gitRoot = FindGitRoot(solutionRoot);

        Assert.Equal(0, RunGit(gitRoot, ["diff", "--check"]));
        Assert.Equal(0, RunGit(gitRoot, ["diff", "--cached", "--check"]));
    }

    private static string FindGitRoot(string startDirectory)
    {
        DirectoryInfo? dir = new(startDirectory);
        while (dir is not null)
        {
            string gitMarker = Path.Combine(dir.FullName, ".git");
            if (Directory.Exists(gitMarker) || File.Exists(gitMarker))
            {
                return dir.FullName;
            }

            dir = dir.Parent;
        }

        throw new InvalidOperationException("Could not locate .git root.");
    }

    private static bool IsGitTracked(string gitRoot, string pathRelativeToGitRoot)
    {
        using System.Diagnostics.Process process = new();
        process.StartInfo = new System.Diagnostics.ProcessStartInfo
        {
            FileName = "git",
            WorkingDirectory = gitRoot,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            ArgumentList = { "ls-files", "--error-unmatch", "--", pathRelativeToGitRoot },
        };

        process.Start();
        process.WaitForExit();
        return process.ExitCode == 0;
    }

    private static int RunGit(string gitRoot, string[] args)
    {
        using System.Diagnostics.Process process = new();
        process.StartInfo = new System.Diagnostics.ProcessStartInfo
        {
            FileName = "git",
            WorkingDirectory = gitRoot,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };

        foreach (string arg in args)
        {
            process.StartInfo.ArgumentList.Add(arg);
        }

        process.Start();
        process.WaitForExit();
        return process.ExitCode;
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
