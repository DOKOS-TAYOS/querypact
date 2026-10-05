namespace Sav.Host.Tests;

public sealed class CliContractTests : SavEnvTestBase
{
    [Fact]
    public void Help_lists_analyze_and_mcp_under_AnalyzeOnly()
    {
        using StringWriter stdout = new();
        using StringWriter stderr = new();

        int exit = Program.Run(["--mode", "AnalyzeOnly", "--help"], stdout, stderr);

        Assert.Equal(0, exit);
        string help = stdout.ToString();
        Assert.Contains("analyze", help, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("mcp", help, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("verify-query", help, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("verify-equivalence", help, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("verify-migration", help, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("attestation", help, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Analyze_help_lists_sql_policy_contract_options()
    {
        using StringWriter stdout = new();
        using StringWriter stderr = new();

        int exit = Program.Run(["--mode", "AnalyzeOnly", "analyze", "--help"], stdout, stderr);

        Assert.Equal(0, exit);
        string help = stdout.ToString();
        Assert.Contains("--sql", help, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("--policy", help, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("--contract", help, StringComparison.OrdinalIgnoreCase);
    }
}
