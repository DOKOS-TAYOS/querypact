using Microsoft.Extensions.Logging;
using Sav.Host.Mcp;

namespace Sav.Security.Tests.Surface;

public sealed class McpStdoutIsolationTests
{
    [Fact]
    public void Mcp_server_documents_stderr_logging_threshold()
    {
        Assert.True(SavMcpServer.LogsToStandardError);
        Assert.Equal(LogLevel.Trace, SavMcpServer.StandardErrorLogThreshold);
    }

    [Fact]
    public void SavMcpServer_run_method_source_configures_stderr_threshold()
    {
        // Contract: implementation must set LogToStandardErrorThreshold so protocol stays on stdout.
        string root = FindRepoRoot();
        string path = Path.Combine(root, "src", "Sav.Host", "Mcp", "SavMcpServer.cs");
        string source = File.ReadAllText(path);
        Assert.Contains("LogToStandardErrorThreshold", source, StringComparison.Ordinal);
        Assert.Contains("AddConsole", source, StringComparison.Ordinal);
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

        throw new InvalidOperationException("Could not locate QueryPact.sln.");
    }
}
