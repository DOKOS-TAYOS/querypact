using System.Diagnostics;
using System.Text;
using System.Text.Json;
using Sav.Host.Composition;
using Sav.Host.Tests.E2E;
using Sav.Infrastructure.Postgres.Tests.Fixtures;

namespace Sav.Host.Tests.Publish;

/// <summary>
/// M011a PUB-SMOKE + P01 analyze on the Chosen packaging profile 1 publish layout.
/// </summary>
public sealed class PublishedAnalyzeP01SmokeTests : SavEnvTestBase
{
    /// <summary>ADR 0002 / spike corpus case P01.</summary>
    public const string P01Sql = "SELECT id, email FROM users WHERE active = true";

    [Fact]
    public void Published_querypact_exe_analyzes_P01_without_docker()
    {
        string publishDir = WinX64PublishLayout.EnsurePublished();
        string exe = Path.Combine(publishDir, "querypact.exe");
        Assert.True(File.Exists(exe), "published querypact.exe missing: " + exe);

        using E2EHostHarness.TempWorkspace workspace = E2EHostHarness.CreateWorkspace(includeContract: false);
        using IDisposable env = E2EHostHarness.ConfigureCliEnvironment(workspace, DiProfile.AnalyzeOnly);

        int exit = WinX64PublishLayout.Run(
            exe,
            publishDir,
            [
                "--mode", "AnalyzeOnly",
                "analyze",
                "--sql", P01Sql,
                "--policy", workspace.PolicyRelativePath,
            ],
            out string stdout,
            out string stderr);

        Assert.True(exit == 0, "exit=" + exit + " stderr=" + stderr + " stdout=" + stdout);
        Assert.True(string.IsNullOrWhiteSpace(stderr), stderr);
        using JsonDocument doc = JsonDocument.Parse(stdout.Trim());
        Assert.True(doc.RootElement.GetProperty("analysis").GetProperty("isParsable").GetBoolean());
        Assert.Contains("Select", doc.RootElement.GetProperty("analysis").GetProperty("ir").GetProperty("statementTypes").EnumerateArray().Select(e => e.GetString()), StringComparer.OrdinalIgnoreCase);
        E2EHostHarness.AssertNoConnectionStringLeak(stdout);
        E2EHostHarness.AssertNoConnectionStringLeak(stderr);
    }

    [Fact]
    public void Published_layout_has_no_pdb_secrets_or_local_dumps()
    {
        string publishDir = WinX64PublishLayout.EnsurePublished();
        // CI #209: SDK XML documentation is a build output, not part of profile 1.
        string[] forbiddenExtensions = [".pdb", ".mdmp", ".dmp", ".log", ".xml"];
        string[] forbiddenNameFragments =
        [
            "appsettings.Development",
            ".env",
            "secrets",
            "credentials",
        ];

        foreach (string path in Directory.EnumerateFiles(publishDir, "*", SearchOption.AllDirectories))
        {
            string name = Path.GetFileName(path);
            string ext = Path.GetExtension(path);
            Assert.DoesNotContain(ext, forbiddenExtensions, StringComparer.OrdinalIgnoreCase);
            foreach (string fragment in forbiddenNameFragments)
            {
                Assert.DoesNotContain(fragment, name, StringComparison.OrdinalIgnoreCase);
            }
        }

        Assert.False(
            File.Exists(Path.Combine(publishDir, "querypact.pdb")),
            "querypact.pdb must not ship in publish output");
    }
}

[Collection(nameof(PostgresRoCollection))]
public sealed class PublishedVerifyQuerySmokeTests : SavEnvTestBase
{
    private readonly PostgresRoFixture _fixture;

    public PublishedVerifyQuerySmokeTests(PostgresRoFixture fixture)
    {
        _fixture = fixture;
    }

    [Fact]
    public void Published_querypact_exe_verify_query_full_mode_from_publish_directory()
    {
        string publishDir = WinX64PublishLayout.EnsurePublished();
        string exe = Path.Combine(publishDir, "querypact.exe");
        Assert.True(File.Exists(exe), "published querypact.exe missing: " + exe);

        string dsnEnv = _fixture.Binding.AliasToDsnEnvVar[PostgresRoFixture.RoAlias];
        using E2EHostHarness.TempWorkspace workspace = E2EHostHarness.CreateWorkspace(
            includeTargets: true,
            aliasToDsnEnvVar: new Dictionary<string, string>
            {
                [PostgresRoFixture.RoAlias] = dsnEnv,
            });

        using IDisposable env = E2EHostHarness.ConfigureCliEnvironment(workspace, DiProfile.Full);

        // empty_result fails on SELECT 1 (one row): still proves session open + native load + verify path.
        int exit = WinX64PublishLayout.Run(
            exe,
            publishDir,
            [
                "--mode", "Full",
                "verify-query",
                "--sql", "SELECT 1",
                "--target", PostgresRoFixture.RoAlias,
                "--policy", workspace.PolicyRelativePath,
                "--contract", workspace.ContractRelativePath,
            ],
            out string stdout,
            out string stderr);

        Assert.True(exit == 0, "exit=" + exit + " stderr=" + stderr + " stdout=" + stdout);
        using JsonDocument doc = JsonDocument.Parse(stdout.Trim());
        Assert.False(string.IsNullOrWhiteSpace(doc.RootElement.GetProperty("attestationId").GetString()));
        JsonElement properties = doc.RootElement.GetProperty("attestation").GetProperty("properties");
        Assert.Contains(
            properties.EnumerateArray(),
            p => string.Equals(p.GetProperty("name").GetString(), "query_succeeds", StringComparison.Ordinal));
        Assert.Contains(
            properties.EnumerateArray(),
            p => string.Equals(p.GetProperty("name").GetString(), "empty_result", StringComparison.Ordinal));
        E2EHostHarness.AssertNoConnectionStringLeak(stdout);
        E2EHostHarness.AssertNoConnectionStringLeak(stderr);
        E2EHostHarness.AssertNoCanary(stdout);
    }
}

internal static class WinX64PublishLayout
{
    private static readonly object Gate = new();
    private static string? _publishDir;

    public static string EnsurePublished()
    {
        // Test-only override: exercise the exact release artifact, not a second publish.
        string? existingDir = Environment.GetEnvironmentVariable("SAV_PUBLISHED_WINX64_DIR");
        if (!string.IsNullOrWhiteSpace(existingDir))
        {
            Assert.True(Path.IsPathFullyQualified(existingDir),
                "SAV_PUBLISHED_WINX64_DIR must be an absolute path.");
            string publishDir = Path.GetFullPath(existingDir);
            Assert.True(File.Exists(Path.Combine(publishDir, "querypact.exe")),
                "Existing release-candidate querypact.exe missing: " + publishDir);
            return publishDir;
        }

        lock (Gate)
        {
            if (_publishDir is not null && File.Exists(Path.Combine(_publishDir, "querypact.exe")))
            {
                return _publishDir;
            }

            string repoRoot = E2EHostHarness.FindRepoRoot();
            string outDir = Path.Combine(repoRoot, "artifacts", "m011a-win-x64");
            if (Directory.Exists(outDir))
            {
                try
                {
                    Directory.Delete(outDir, recursive: true);
                }
                catch (IOException)
                {
                    // Best-effort; publish -o overwrites.
                }
            }

            Directory.CreateDirectory(outDir);
            string hostCsproj = Path.Combine(repoRoot, "src", "Sav.Host", "Sav.Host.csproj");
            int publishExit = Run(
                "dotnet",
                workingDirectory: repoRoot,
                args:
                [
                    "publish", hostCsproj,
                    "-c", "Release",
                    "-r", "win-x64",
                    "--self-contained", "true",
                    "-p:PublishSingleFile=true",
                    "-p:IncludeNativeLibrariesForSelfExtract=true",
                    "-p:DebugType=None",
                    "-p:PublishDocumentationFile=false",
                    "-p:PublishReferencesDocumentationFiles=false",
                    "-p:DebugSymbols=false",
                    "-o", outDir,
                ],
                out string publishStdout,
                out string publishStderr);
            Assert.True(
                publishExit == 0,
                "dotnet publish failed: " + publishStdout + Environment.NewLine + publishStderr);
            Assert.True(File.Exists(Path.Combine(outDir, "querypact.exe")), "querypact.exe missing after publish");
            _publishDir = outDir;
            return outDir;
        }
    }

    public static int Run(
        string fileName,
        string workingDirectory,
        IReadOnlyList<string> args,
        out string stdout,
        out string stderr)
    {
        ProcessStartInfo psi = new()
        {
            FileName = fileName,
            WorkingDirectory = workingDirectory,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        foreach (string arg in args)
        {
            psi.ArgumentList.Add(arg);
        }

        using Process process = Process.Start(psi)!;
        StringBuilder outBuilder = new();
        StringBuilder errBuilder = new();
        process.OutputDataReceived += (_, e) =>
        {
            if (e.Data is not null)
            {
                outBuilder.AppendLine(e.Data);
            }
        };
        process.ErrorDataReceived += (_, e) =>
        {
            if (e.Data is not null)
            {
                errBuilder.AppendLine(e.Data);
            }
        };
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();
        Assert.True(process.WaitForExit(600_000), "process timed out: " + fileName);
        // Drain async readers.
        process.WaitForExit();
        stdout = outBuilder.ToString();
        stderr = errBuilder.ToString();
        return process.ExitCode;
    }
}
