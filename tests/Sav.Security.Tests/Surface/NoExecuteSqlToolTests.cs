using Sav.Host.Composition;
using Sav.Host.Mcp;

namespace Sav.Security.Tests.Surface;

public sealed class NoExecuteSqlToolTests
{
    [Fact]
    public void Mcp_catalogs_never_include_execute_sql()
    {
        Assert.DoesNotContain("execute_sql", SavMcpServer.GetToolNames(DiProfile.AnalyzeOnly));
        Assert.DoesNotContain("execute_sql", SavMcpServer.GetToolNames(DiProfile.Full));
    }

    [Fact]
    public void Host_assembly_has_no_execute_sql_tool_type()
    {
        Type? execute = typeof(Sav.Host.Program).Assembly
            .GetTypes()
            .FirstOrDefault(t =>
                t.Name.Contains("ExecuteSql", StringComparison.OrdinalIgnoreCase)
                || t.FullName?.Contains("execute_sql", StringComparison.OrdinalIgnoreCase) == true);
        Assert.Null(execute);
    }
}
