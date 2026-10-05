using System.Diagnostics;
using System.Text;
using Sav.Application.Abstractions;
using Sav.Infrastructure.Postgres.Parsing;

namespace Sav.Infrastructure.Postgres.Tests.Parsing;

public sealed class NativeParserPublishSmokeTests
{
    [Fact]
    public void Profile1_self_contained_single_file_publish_loads_chosen_parser()
    {
        string repoRoot = FindRepoRoot();
        string outDir = Path.Combine(repoRoot, "artifacts", "m004a-native-smoke");
        try
        {
            if (Directory.Exists(outDir))
            {
                Directory.Delete(outDir, recursive: true);
            }

            Directory.CreateDirectory(outDir);
            string probeProjDir = Path.Combine(outDir, "probe");
            Directory.CreateDirectory(probeProjDir);
            string postgresCsproj = Path.Combine(repoRoot, "src", "Sav.Infrastructure.Postgres", "Sav.Infrastructure.Postgres.csproj");
            string probeCsproj = Path.Combine(probeProjDir, "M004aSmokeProbe.csproj");
            File.WriteAllText(
                probeCsproj,
                $"""
                <Project Sdk="Microsoft.NET.Sdk">
                  <PropertyGroup>
                    <OutputType>Exe</OutputType>
                    <TargetFramework>net10.0</TargetFramework>
                    <ImplicitUsings>enable</ImplicitUsings>
                    <Nullable>enable</Nullable>
                  </PropertyGroup>
                  <ItemGroup>
                    <ProjectReference Include="{postgresCsproj}" />
                  </ItemGroup>
                  <Import Project="{Path.Combine(repoRoot, "build", "NativeLibPgQuery.props")}" />
                </Project>
                """,
                Encoding.UTF8);
            File.WriteAllText(
                Path.Combine(probeProjDir, "Program.cs"),
                """
                using Sav.Infrastructure.Postgres.Parsing;
                var parser = new LibPgQuerySqlParser();
                var result = parser.Parse("SELECT 1 AS value", CancellationToken.None);
                return result.Success && result.Ir is not null ? 0 : 2;
                """,
                Encoding.UTF8);

            string publishDir = Path.Combine(outDir, "publish");
            int publishExit = Run(
                "dotnet",
                $"publish \"{probeCsproj}\" -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:DebugSymbols=false -p:DebugType=none -o \"{publishDir}\"",
                out string publishLog);
            Assert.True(publishExit == 0, publishLog);

            string exe = Directory.GetFiles(publishDir, "M004aSmokeProbe.exe").Single();
            int runExit = Run(exe, string.Empty, out string runLog);
            Assert.True(runExit == 0, runLog);

            // In-process Chosen package sanity (same adapter).
            ISqlParser parser = new LibPgQuerySqlParser();
            SqlParseResult parse = parser.Parse("SELECT 1", CancellationToken.None);
            Assert.True(parse.Success);
        }
        finally
        {
            if (Directory.Exists(outDir))
            {
                try
                {
                    Directory.Delete(outDir, recursive: true);
                }
                catch (IOException)
                {
                    // Best-effort cleanup so sole-Exe security guards stay green.
                }
            }
        }
    }

    private static int Run(string fileName, string args, out string log)
    {
        ProcessStartInfo psi = new()
        {
            FileName = fileName,
            Arguments = args,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        using Process process = Process.Start(psi)!;
        string stdout = process.StandardOutput.ReadToEnd();
        string stderr = process.StandardError.ReadToEnd();
        Assert.True(process.WaitForExit(300_000), "process timed out");
        log = stdout + Environment.NewLine + stderr;
        return process.ExitCode;
    }

    private static string FindRepoRoot()
    {
        DirectoryInfo? cursor = new(AppContext.BaseDirectory);
        while (cursor is not null)
        {
            if (File.Exists(Path.Combine(cursor.FullName, "QueryPact.sln")))
            {
                return cursor.FullName;
            }

            cursor = cursor.Parent;
        }

        throw new InvalidOperationException("QueryPact.sln not found.");
    }
}
