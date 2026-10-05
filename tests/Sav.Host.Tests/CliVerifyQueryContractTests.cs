using Sav.Infrastructure.Storage.Attestations;

namespace Sav.Host.Tests;

public sealed class CliVerifyQueryContractTests : SavEnvTestBase
{
    [Fact]
    public void Verify_query_help_lists_required_options_without_explain_analyze()
    {
        using IDisposable key = EnvScope.Set(
            AttestationHmacKeyDecoder.EnvironmentVariableName,
            "base64:" + Convert.ToBase64String(Enumerable.Repeat((byte)0x46, 32).ToArray()));

        using StringWriter stdout = new();
        using StringWriter stderr = new();
        int exit = Program.Run(["--mode", "Full", "verify-query", "--help"], stdout, stderr);
        Assert.Equal(0, exit);
        string help = stdout.ToString();
        Assert.Contains("--sql", help, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("--target", help, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("--policy", help, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("--contract", help, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("explain-analyze", help, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("EXPLAIN ANALYZE", help, StringComparison.OrdinalIgnoreCase);
    }
}
