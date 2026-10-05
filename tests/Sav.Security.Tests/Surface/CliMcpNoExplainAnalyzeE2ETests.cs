using System.Reflection;
using Sav.Host;
using Sav.Host.Mcp.Tools;
using Sav.Infrastructure.Storage.Attestations;

namespace Sav.Security.Tests.Surface;

/// <summary>
/// M009e: equivalence/migration CLI + MCP surfaces expose no EXPLAIN ANALYZE option.
/// </summary>
[Collection(SecurityEnvCollectionDefinition.Name)]
public sealed class CliMcpNoExplainAnalyzeE2ETests
{
    [Fact]
    public void Cli_equivalence_and_migration_help_have_no_explain_analyze()
    {
        string? priorKey = Environment.GetEnvironmentVariable(AttestationHmacKeyDecoder.EnvironmentVariableName);
        try
        {
            Environment.SetEnvironmentVariable(
                AttestationHmacKeyDecoder.EnvironmentVariableName,
                "base64:" + Convert.ToBase64String(Enumerable.Repeat((byte)0x73, 32).ToArray()));

            foreach (string command in new[] { "verify-equivalence", "verify-migration" })
            {
                using StringWriter stdout = new();
                using StringWriter stderr = new();
                int exit = Program.Run(["--mode", "Full", command, "--help"], stdout, stderr);
                Assert.Equal(0, exit);
                AssertNoExplainAnalyze(stdout.ToString());
                AssertNoExplainAnalyze(stderr.ToString());
            }
        }
        finally
        {
            Environment.SetEnvironmentVariable(AttestationHmacKeyDecoder.EnvironmentVariableName, priorKey);
        }
    }

    [Fact]
    public void Mcp_equivalence_and_migration_tools_have_no_explain_analyze_parameter()
    {
        AssertNoExplainAnalyzeParameter(
            typeof(VerifyEquivalenceTool).GetMethod(nameof(VerifyEquivalenceTool.VerifyEquivalence))!);
        AssertNoExplainAnalyzeParameter(
            typeof(VerifyMigrationTool).GetMethod(nameof(VerifyMigrationTool.VerifyMigration))!);

        AssertNoExplainAnalyze(typeof(VerifyEquivalenceTool).FullName ?? string.Empty);
        AssertNoExplainAnalyze(typeof(VerifyMigrationTool).FullName ?? string.Empty);

        foreach (ParameterInfo parameter in typeof(VerifyEquivalenceTool)
                     .GetMethod(nameof(VerifyEquivalenceTool.VerifyEquivalence))!
                     .GetParameters())
        {
            AssertNoExplainAnalyze(parameter.Name ?? string.Empty);
            AssertNoExplainAnalyze(parameter.ParameterType.Name);
        }

        foreach (ParameterInfo parameter in typeof(VerifyMigrationTool)
                     .GetMethod(nameof(VerifyMigrationTool.VerifyMigration))!
                     .GetParameters())
        {
            AssertNoExplainAnalyze(parameter.Name ?? string.Empty);
            AssertNoExplainAnalyze(parameter.ParameterType.Name);
        }
    }

    private static void AssertNoExplainAnalyzeParameter(MethodInfo method)
    {
        foreach (ParameterInfo parameter in method.GetParameters())
        {
            string name = parameter.Name ?? string.Empty;
            Assert.DoesNotContain("explain", name, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("analyze", name, StringComparison.OrdinalIgnoreCase);
        }
    }

    private static void AssertNoExplainAnalyze(string text)
    {
        Assert.DoesNotContain("explain-analyze", text, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("EXPLAIN ANALYZE", text, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("--explain", text, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("explainAnalyze", text, StringComparison.Ordinal);
        Assert.DoesNotContain("ExplainAnalyze", text, StringComparison.Ordinal);
    }
}
