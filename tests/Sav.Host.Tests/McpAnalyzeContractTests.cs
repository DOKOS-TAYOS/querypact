using Sav.Host.Composition;
using Sav.Host.Mcp;

namespace Sav.Host.Tests;

public sealed class McpAnalyzeContractTests : SavEnvTestBase
{
    [Fact]
    public void AnalyzeOnly_tool_catalog_is_analyze_sql_only()
    {
        IReadOnlyList<string> tools = SavMcpServer.GetToolNames(DiProfile.AnalyzeOnly);
        Assert.Equal(["analyze_sql"], tools);
        Assert.DoesNotContain("get_attestation", tools);
        Assert.DoesNotContain("verify_query", tools);
        Assert.DoesNotContain("execute_sql", tools);
    }

    [Fact]
    public void Mcp_serve_help_exists_under_AnalyzeOnly()
    {
        using StringWriter stdout = new();
        using StringWriter stderr = new();
        int exit = Program.Run(["--mode", "AnalyzeOnly", "mcp", "serve", "--help"], stdout, stderr);
        Assert.Equal(0, exit);
        Assert.Contains("serve", stdout.ToString(), StringComparison.OrdinalIgnoreCase);
    }
}
