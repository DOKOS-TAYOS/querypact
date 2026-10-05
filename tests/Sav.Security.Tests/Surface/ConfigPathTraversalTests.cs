using Sav.Domain.Errors;
using Sav.Infrastructure.Config.Paths;

namespace Sav.Security.Tests.Surface;

public sealed class ConfigPathTraversalTests
{
    [Fact]
    public void Accepts_relative_path_under_config_root()
    {
        using TempConfigRoot root = TempConfigRoot.Create();
        File.WriteAllText(Path.Combine(root.Path, "policy.yaml"), "id: p1");
        ConfigPathResolver resolver = root.CreateResolver();

        string resolved = resolver.ResolveUnderConfigRoot("policy.yaml");

        Assert.Equal(Path.GetFullPath(Path.Combine(root.Path, "policy.yaml")), resolved);
    }

    [Fact]
    public void File_system_root_stays_absolute_and_can_resolve_existing_descendant()
    {
        using TempConfigRoot root = TempConfigRoot.Create();
        string candidate = Path.Combine(root.Path, "policy.yaml");
        File.WriteAllText(candidate, "id: p1");
        string filesystemRoot = Path.GetPathRoot(root.Path)!;
        string relative = Path.GetRelativePath(filesystemRoot, candidate);

        ConfigPathResolver resolver = new(new ConfigRootOptions { ConfigRoot = filesystemRoot });
        string resolved = resolver.ResolveUnderConfigRoot(relative);

        Assert.Equal(Path.GetFullPath(candidate), resolved);
        Assert.True(Path.IsPathFullyQualified(resolved));
    }

    [Fact]
    public void Rejects_parent_directory_escape()
    {
        using TempConfigRoot root = TempConfigRoot.Create();
        ConfigPathResolver resolver = root.CreateResolver();

        SavException ex = Assert.Throws<SavException>(
            () => resolver.ResolveUnderConfigRoot("../outside.yaml"));

        Assert.Equal(SavErrorCode.PathNotAllowed, ex.Code);
        Assert.DoesNotContain(root.SiblingSecretContents, ex.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(root.SiblingSecretPath, ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Rejects_absolute_path_outside_root()
    {
        using TempConfigRoot root = TempConfigRoot.Create();
        ConfigPathResolver resolver = root.CreateResolver();

        SavException ex = Assert.Throws<SavException>(
            () => resolver.ResolveUnderConfigRoot(root.SiblingSecretPath));

        Assert.Equal(SavErrorCode.PathNotAllowed, ex.Code);
        Assert.DoesNotContain(root.SiblingSecretContents, ex.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(root.SiblingSecretPath, ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Rejects_empty_path()
    {
        using TempConfigRoot root = TempConfigRoot.Create();
        ConfigPathResolver resolver = root.CreateResolver();

        SavException ex = Assert.Throws<SavException>(() => resolver.ResolveUnderConfigRoot("  "));

        Assert.Equal(SavErrorCode.PathNotAllowed, ex.Code);
    }

    [Fact]
    public void Symlink_escape_is_rejected_when_creatable_else_documents_residual()
    {
        using TempConfigRoot root = TempConfigRoot.Create();
        string linkPath = Path.Combine(root.Path, "escape.link");
        bool created;

        try
        {
            // Sibling secret is a file; prefer File.CreateSymbolicLink when available.
            File.CreateSymbolicLink(linkPath, root.SiblingSecretPath);
            created = true;
        }
        catch (Exception createEx) when (createEx is UnauthorizedAccessException or IOException or PlatformNotSupportedException)
        {
            try
            {
                Directory.CreateSymbolicLink(linkPath, root.SiblingSecretPath);
                created = true;
            }
            catch (Exception dirEx) when (dirEx is UnauthorizedAccessException or IOException or PlatformNotSupportedException)
            {
                created = false;
            }
        }

        if (!created)
        {
            // SYM-WIN MEDIUM residual: not proven closed on this agent.
            string findingsPath = FindSecurityFindingsPath();
            string findings = File.ReadAllText(findingsPath);
            Assert.Contains("symlink_windows_detection_limit", findings, StringComparison.Ordinal);
            return;
        }

        ConfigPathResolver resolver = root.CreateResolver();
        SavException rejected = Assert.Throws<SavException>(() => resolver.ResolveUnderConfigRoot("escape.link"));

        Assert.Equal(SavErrorCode.PathNotAllowed, rejected.Code);
        Assert.DoesNotContain(root.SiblingSecretContents, rejected.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Unix_rejects_absolute_path_with_different_root_casing()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        using TempConfigRoot root = TempConfigRoot.Create();
        string? parent = Path.GetDirectoryName(root.Path);
        Assert.NotNull(parent);
        string differentlyCasedRoot = Path.Combine(parent, "CONFIG-ROOT");
        Directory.CreateDirectory(differentlyCasedRoot);
        string candidate = Path.Combine(differentlyCasedRoot, "policy.yaml");
        File.WriteAllText(candidate, "id: outside");

        SavException ex = Assert.Throws<SavException>(
            () => root.CreateResolver().ResolveUnderConfigRoot(candidate));

        Assert.Equal(SavErrorCode.PathNotAllowed, ex.Code);
    }

    [Fact]
    public void Unix_rejects_a_symlink_in_an_intermediate_directory()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        using TempConfigRoot root = TempConfigRoot.Create();
        string? parent = Path.GetDirectoryName(root.Path);
        Assert.NotNull(parent);
        string outside = Path.Combine(parent, "outside");
        Directory.CreateDirectory(outside);
        File.WriteAllText(Path.Combine(outside, "secret.yaml"), root.SiblingSecretContents);

        string ordinaryDirectory = Path.Combine(root.Path, "ordinary");
        Directory.CreateDirectory(ordinaryDirectory);
        Directory.CreateSymbolicLink(Path.Combine(ordinaryDirectory, "linked"), outside);

        SavException ex = Assert.Throws<SavException>(() =>
            root.CreateResolver().ResolveUnderConfigRoot(
                Path.Combine("ordinary", "linked", "secret.yaml")));

        Assert.Equal(SavErrorCode.PathNotAllowed, ex.Code);
        Assert.DoesNotContain(root.SiblingSecretContents, ex.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(root.SiblingSecretPath, ex.Message, StringComparison.Ordinal);
    }

    private static string FindSecurityFindingsPath()
    {
        string? dir = AppContext.BaseDirectory;
        while (dir is not null)
        {
            string candidate = Path.Combine(dir, "docs", "security", "findings.md");
            if (File.Exists(candidate))
            {
                return candidate;
            }

            dir = Directory.GetParent(dir)?.FullName;
        }

        throw new InvalidOperationException("docs/security/findings.md not found.");
    }

    private sealed class TempConfigRoot : IDisposable
    {
        private TempConfigRoot(string path, string siblingSecretPath, string siblingSecretContents)
        {
            Path = path;
            SiblingSecretPath = siblingSecretPath;
            SiblingSecretContents = siblingSecretContents;
        }

        public string Path { get; }

        public string SiblingSecretPath { get; }

        public string SiblingSecretContents { get; }

        public static TempConfigRoot Create()
        {
            string baseDir = System.IO.Path.Combine(
                System.IO.Path.GetTempPath(),
                "sav-config-path-" + Guid.NewGuid().ToString("N"));
            string root = System.IO.Path.Combine(baseDir, "config-root");
            Directory.CreateDirectory(root);
            string sibling = System.IO.Path.Combine(baseDir, "secret-outside.yaml");
            const string secret = "super-secret-token-do-not-leak";
            File.WriteAllText(sibling, secret);
            return new TempConfigRoot(root, sibling, secret);
        }

        public ConfigPathResolver CreateResolver()
        {
            return new ConfigPathResolver(new ConfigRootOptions { ConfigRoot = Path });
        }

        public void Dispose()
        {
            string? parent = System.IO.Path.GetDirectoryName(Path);
            if (parent is not null && Directory.Exists(parent))
            {
                try
                {
                    Directory.Delete(parent, recursive: true);
                }
                catch (IOException)
                {
                    // best-effort cleanup
                }
            }
        }
    }
}
