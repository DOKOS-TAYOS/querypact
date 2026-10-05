namespace Sav.Host.Tests;

public sealed class HostStartupModeAnalyzeOnlyTests : SavEnvTestBase
{
    [Fact]
    public void AnalyzeOnly_starts_without_hmac_and_excludes_verify_get_commands()
    {
        using IDisposable clearKey = EnvScope.Set(
            Infrastructure.Storage.Attestations.AttestationHmacKeyDecoder.EnvironmentVariableName,
            null);

        using StringWriter stdout = new();
        using StringWriter stderr = new();
        int exit = Program.Run(["--mode", "AnalyzeOnly", "--help"], stdout, stderr);

        Assert.Equal(0, exit);
        Assert.True(string.IsNullOrWhiteSpace(stderr.ToString()));
        string help = stdout.ToString();
        Assert.Contains("analyze", help, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("verify-query", help, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("attestation", help, StringComparison.OrdinalIgnoreCase);
    }
}
