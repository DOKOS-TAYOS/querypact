using System.Text.Json;
using Sav.Domain.Errors;
using Sav.Host.Composition;
using Sav.Host.Tests.E2E;

namespace Sav.Host.Tests;

/// <summary>
/// CLI policy/contract path confused-deputy / LFI (M009a gap closed for M010a-A-corpus-w1).
/// </summary>
public sealed class CliPathTraversalTests : SavEnvTestBase
{
    [Theory]
    [InlineData("../outside.yaml")]
    [InlineData("..\\outside.yaml")]
    [InlineData("/etc/passwd")]
    public void Analyze_cli_rejects_policy_path_escape(string escapePath)
    {
        using E2EHostHarness.TempWorkspace workspace = E2EHostHarness.CreateWorkspace(includeContract: false);
        using IDisposable env = E2EHostHarness.ConfigureCliEnvironment(workspace, DiProfile.AnalyzeOnly);

        using StringWriter stdout = new();
        using StringWriter stderr = new();
        int exit = Program.Run(
            [
                "--mode", "AnalyzeOnly",
                "analyze",
                "--sql", "SELECT 1",
                "--policy", escapePath,
            ],
            stdout,
            stderr);

        Assert.Equal(1, exit);
        Assert.True(string.IsNullOrWhiteSpace(stdout.ToString()));
        string err = stderr.ToString();
        using JsonDocument doc = JsonDocument.Parse(err.Trim());
        Assert.Equal(SavErrorCode.PathNotAllowed, doc.RootElement.GetProperty("error").GetString());
        E2EHostHarness.AssertNoConnectionStringLeak(err);
        Assert.DoesNotContain(workspace.ConfigRoot, err, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Analyze_cli_rejects_contract_path_escape()
    {
        using E2EHostHarness.TempWorkspace workspace = E2EHostHarness.CreateWorkspace(includeContract: false);
        using IDisposable env = E2EHostHarness.ConfigureCliEnvironment(workspace, DiProfile.AnalyzeOnly);

        using StringWriter stdout = new();
        using StringWriter stderr = new();
        int exit = Program.Run(
            [
                "--mode", "AnalyzeOnly",
                "analyze",
                "--sql", "SELECT 1",
                "--policy", workspace.PolicyRelativePath,
                "--contract", "../outside-contract.yaml",
            ],
            stdout,
            stderr);

        Assert.Equal(1, exit);
        Assert.True(string.IsNullOrWhiteSpace(stdout.ToString()));
        using JsonDocument doc = JsonDocument.Parse(stderr.ToString().Trim());
        Assert.Equal(SavErrorCode.PathNotAllowed, doc.RootElement.GetProperty("error").GetString());
    }
}
