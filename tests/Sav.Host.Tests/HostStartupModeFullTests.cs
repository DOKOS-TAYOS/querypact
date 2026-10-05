using Sav.Domain.Errors;
using Sav.Infrastructure.Storage.Attestations;

namespace Sav.Host.Tests;

public sealed class HostStartupModeFullTests : SavEnvTestBase
{
    [Fact]
    public void Full_without_hmac_refuses_attestation_get()
    {
        using IDisposable clearKey = EnvScope.Set(AttestationHmacKeyDecoder.EnvironmentVariableName, null);

        using StringWriter stdout = new();
        using StringWriter stderr = new();
        int exit = Program.Run(
            ["--mode", "Full", "attestation", "get", "--id", Guid.NewGuid().ToString("D")],
            stdout,
            stderr);

        Assert.NotEqual(0, exit);
        Assert.Contains(SavErrorCode.AttestationHmacKeyMissing, stderr.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void Full_with_hmac_help_lists_attestation_and_verify()
    {
        using IDisposable key = EnvScope.Set(
            AttestationHmacKeyDecoder.EnvironmentVariableName,
            "base64:" + Convert.ToBase64String(Enumerable.Repeat((byte)0x43, 32).ToArray()));

        using StringWriter stdout = new();
        using StringWriter stderr = new();
        int exit = Program.Run(["--mode", "Full", "--help"], stdout, stderr);

        Assert.Equal(0, exit);
        string help = stdout.ToString();
        Assert.Contains("attestation", help, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("verify-query", help, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("verify-equivalence", help, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("verify-migration", help, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Full_subcommand_help_does_not_require_hmac()
    {
        using IDisposable clearKey = EnvScope.Set(
            AttestationHmacKeyDecoder.EnvironmentVariableName,
            null);

        string[][] helpCommands =
        [
            ["--mode", "Full", "verify-query", "--help"],
            ["--mode", "Full", "verify-equivalence", "--help"],
            ["--mode", "Full", "verify-migration", "--help"],
            ["--mode", "Full", "attestation", "get", "--help"],
        ];

        foreach (string[] args in helpCommands)
        {
            using StringWriter stdout = new();
            using StringWriter stderr = new();

            int exit = Program.Run(args, stdout, stderr);

            Assert.Equal(0, exit);
            Assert.DoesNotContain(
                SavErrorCode.AttestationHmacKeyMissing,
                stderr.ToString(),
                StringComparison.Ordinal);
            Assert.False(string.IsNullOrWhiteSpace(stdout.ToString()));
        }
    }

    [Fact]
    public void Full_invalid_hmac_encoding_refuses_verify_query()
    {
        using IDisposable key = EnvScope.Set(AttestationHmacKeyDecoder.EnvironmentVariableName, "opaque-utf8-key");

        using StringWriter stdout = new();
        using StringWriter stderr = new();
        int exit = Program.Run(
            [
                "--mode", "Full",
                "verify-query",
                "--sql", "SELECT 1",
                "--target", "t",
                "--policy", "p.yaml",
                "--contract", "c.yaml",
            ],
            stdout,
            stderr);

        Assert.NotEqual(0, exit);
        Assert.Contains(SavErrorCode.AttestationHmacKeyInvalidEncoding, stderr.ToString(), StringComparison.Ordinal);
    }
}
