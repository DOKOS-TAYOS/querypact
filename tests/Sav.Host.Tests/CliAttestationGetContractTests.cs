using Sav.Infrastructure.Storage.Attestations;

namespace Sav.Host.Tests;

public sealed class CliAttestationGetContractTests : SavEnvTestBase
{
    [Fact]
    public void Attestation_get_is_absent_under_AnalyzeOnly()
    {
        using StringWriter stdout = new();
        using StringWriter stderr = new();
        int exit = Program.Run(["--mode", "AnalyzeOnly", "--help"], stdout, stderr);
        Assert.Equal(0, exit);
        Assert.DoesNotContain("attestation", stdout.ToString(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Attestation_get_help_has_id_and_no_dsn()
    {
        using IDisposable key = EnvScope.Set(
            AttestationHmacKeyDecoder.EnvironmentVariableName,
            "base64:" + Convert.ToBase64String(Enumerable.Repeat((byte)0x45, 32).ToArray()));

        using StringWriter stdout = new();
        using StringWriter stderr = new();
        int exit = Program.Run(["--mode", "Full", "attestation", "get", "--help"], stdout, stderr);
        Assert.Equal(0, exit);
        string help = stdout.ToString();
        Assert.Contains("--id", help, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("--dsn", help, StringComparison.OrdinalIgnoreCase);
    }
}
