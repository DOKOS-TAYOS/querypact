using Sav.Host.Composition;
using Sav.Host.Mcp;

namespace Sav.Host.Tests;

public sealed class McpVerifyQueryContractTests
{
    [Fact]
    public void Full_catalog_includes_verify_query()
    {
        Assert.Contains("verify_query", SavMcpServer.GetToolNames(DiProfile.Full));
    }

    [Fact]
    public void AnalyzeOnly_catalog_excludes_verify_query()
    {
        Assert.DoesNotContain("verify_query", SavMcpServer.GetToolNames(DiProfile.AnalyzeOnly));
    }
}
