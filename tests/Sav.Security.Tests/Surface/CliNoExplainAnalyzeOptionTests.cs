using Sav.Infrastructure.Storage.Attestations;

namespace Sav.Security.Tests.Surface;

[Collection(SecurityEnvCollectionDefinition.Name)]
public sealed class CliNoExplainAnalyzeOptionTests
{
    [Fact]
    public void Verify_surfaces_help_has_no_explain_analyze_option()
    {
        string? priorMode = Environment.GetEnvironmentVariable("SAV_MODE");
        string? priorKey = Environment.GetEnvironmentVariable(AttestationHmacKeyDecoder.EnvironmentVariableName);
        try
        {
            Environment.SetEnvironmentVariable(
                AttestationHmacKeyDecoder.EnvironmentVariableName,
                "base64:" + Convert.ToBase64String(Enumerable.Repeat((byte)0x49, 32).ToArray()));

            foreach (string[] args in new[]
                     {
                         new[] { "--mode", "Full", "verify-query", "--help" },
                         new[] { "--mode", "Full", "verify-equivalence", "--help" },
                         new[] { "--mode", "Full", "verify-migration", "--help" },
                         new[] { "--mode", "AnalyzeOnly", "analyze", "--help" },
                     })
            {
                using StringWriter stdout = new();
                using StringWriter stderr = new();
                int exit = Sav.Host.Program.Run(args, stdout, stderr);
                Assert.Equal(0, exit);
                string help = stdout.ToString();
                Assert.DoesNotContain("explain-analyze", help, StringComparison.OrdinalIgnoreCase);
                Assert.DoesNotContain("EXPLAIN ANALYZE", help, StringComparison.OrdinalIgnoreCase);
                Assert.DoesNotContain("--explain", help, StringComparison.OrdinalIgnoreCase);
            }
        }
        finally
        {
            Environment.SetEnvironmentVariable("SAV_MODE", priorMode);
            Environment.SetEnvironmentVariable(AttestationHmacKeyDecoder.EnvironmentVariableName, priorKey);
        }
    }
}
