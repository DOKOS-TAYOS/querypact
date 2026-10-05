using Sav.Infrastructure.Storage.Attestations;

namespace Sav.Host.Tests;

public sealed class CliRejectDsnArgumentTests : SavEnvTestBase
{
    [Fact]
    public void Analyze_help_has_no_dsn_option()
    {
        using StringWriter stdout = new();
        using StringWriter stderr = new();

        int exit = Program.Run(["--mode", "AnalyzeOnly", "analyze", "--help"], stdout, stderr);

        Assert.Equal(0, exit);
        string help = stdout.ToString();
        Assert.DoesNotContain("--dsn", help, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("connection string", help, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Host=", help, StringComparison.Ordinal);
    }

    [Fact]
    public void Verify_query_help_has_no_dsn_option()
    {
        using IDisposable key = EnvScope.Set(
            AttestationHmacKeyDecoder.EnvironmentVariableName,
            "base64:" + Convert.ToBase64String(Enumerable.Repeat((byte)0x42, 32).ToArray()));

        using StringWriter stdout = new();
        using StringWriter stderr = new();
        int exit = Program.Run(["--mode", "Full", "verify-query", "--help"], stdout, stderr);

        Assert.Equal(0, exit);
        string help = stdout.ToString();
        Assert.DoesNotContain("--dsn", help, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("--target", help, StringComparison.OrdinalIgnoreCase);
    }
}
