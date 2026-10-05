using Sav.Application.Abstractions;
using Sav.Application.Analyze;
using Sav.Host.Mcp.Tools;

namespace Sav.Host.Tests.Mcp;

public sealed class McpToolInternalErrorTests
{
    private const string Canary = "CANARY_MCP_STACK_do_not_egress@example.invalid";

    [Fact]
    public async Task AnalyzeSql_non_SavException_returns_internal_error_without_stack_or_canary()
    {
        AnalyzeSqlTool tool = new(new ThrowingAnalyzeUseCase());
        string json = await tool.AnalyzeSql("SELECT 1", "p.yaml", null, CancellationToken.None);

        Assert.Contains("internal_error", json, StringComparison.Ordinal);
        Assert.DoesNotContain(Canary, json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("at Sav.", json, StringComparison.Ordinal);
        Assert.DoesNotContain("ThrowingAnalyzeUseCase", json, StringComparison.Ordinal);
        Assert.DoesNotContain("StackTrace", json, StringComparison.OrdinalIgnoreCase);
    }

    private sealed class ThrowingAnalyzeUseCase : IAnalyzeSqlUseCase
    {
        public Task<AnalyzeSqlResponse> ExecuteAsync(
            AnalyzeSqlRequest request,
            CancellationToken cancellationToken) =>
            throw new InvalidOperationException($"boom {Canary}\n   at Sav.Host.Tests.Mcp.ThrowingAnalyzeUseCase.ExecuteAsync()");
    }
}
