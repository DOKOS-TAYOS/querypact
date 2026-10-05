using Sav.Host.Composition;
using Sav.Host.Mcp;
using Sav.Infrastructure.Storage.Attestations;

namespace Sav.Host.Tests;

public sealed class McpGetAttestationContractTests : SavEnvTestBase
{
    [Fact]
    public void Full_catalog_includes_get_attestation()
    {
        IReadOnlyList<string> tools = SavMcpServer.GetToolNames(DiProfile.Full);
        Assert.Contains("get_attestation", tools);
        Assert.Contains("analyze_sql", tools);
    }

    [Fact]
    public void AnalyzeOnly_catalog_excludes_get_attestation()
    {
        Assert.DoesNotContain("get_attestation", SavMcpServer.GetToolNames(DiProfile.AnalyzeOnly));
    }

    [Fact]
    public void Attestation_get_help_exists_under_Full()
    {
        using IDisposable key = EnvScope.Set(
            AttestationHmacKeyDecoder.EnvironmentVariableName,
            "base64:" + Convert.ToBase64String(Enumerable.Repeat((byte)0x44, 32).ToArray()));

        using StringWriter stdout = new();
        using StringWriter stderr = new();
        int exit = Program.Run(["--mode", "Full", "attestation", "get", "--help"], stdout, stderr);
        Assert.Equal(0, exit);
        Assert.Contains("--id", stdout.ToString(), StringComparison.OrdinalIgnoreCase);
    }
}
