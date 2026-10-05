using System.Text.Json;
using System.Text.RegularExpressions;

namespace Sav.Security.Tests.Regressions;

/// <summary>
/// M010b-A bar lock: MVP-A track must record 0 open Critical and 0 open High
/// (or overflow to M010c-A). With no approved C/H to remediate, this asserts the findings file.
/// </summary>
public sealed class M010bAFindingsBarTests
{
    [Fact]
    public void M010b_a_findings_records_zero_open_critical_and_high()
    {
        string path = Path.Combine(
            global::Sav.Security.Tests.SecurityAnalyzeHarness.FindRepoRoot(),
            "docs",
            "security",
            "m010b-a-findings.md");
        Assert.True(File.Exists(path), "Missing findings file: " + path);

        string markdown = File.ReadAllText(path);
        Match match = Regex.Match(
            markdown,
            "```json\\s*(?<json>\\{[\\s\\S]*?\\})\\s*```",
            RegexOptions.CultureInvariant);
        Assert.True(match.Success, "Expected machine-readable JSON block in m010b-a-findings.md");

        using JsonDocument doc = JsonDocument.Parse(match.Groups["json"].Value);
        JsonElement root = doc.RootElement;

        Assert.Equal(1, root.GetProperty("schemaVersion").GetInt32());
        Assert.Equal("MVP-A", root.GetProperty("band").GetString());
        Assert.Equal("M010b-A", root.GetProperty("milestone").GetString());
        Assert.Equal(0, root.GetProperty("openCritical").GetInt32());
        Assert.Equal(0, root.GetProperty("openHigh").GetInt32());
        Assert.True(root.GetProperty("skipM010cA").GetBoolean());
        Assert.Equal(JsonValueKind.Null, root.GetProperty("overflowMilestone").ValueKind);
    }

    [Fact]
    public void Medium_symlink_waiver_is_explicit_in_findings()
    {
        string path = Path.Combine(
            global::Sav.Security.Tests.SecurityAnalyzeHarness.FindRepoRoot(),
            "docs",
            "security",
            "m010b-a-findings.md");
        string markdown = File.ReadAllText(path);
        Assert.Contains("symlink_windows_detection_limit", markdown, StringComparison.Ordinal);
        Assert.Contains("SYM-WIN", markdown, StringComparison.Ordinal);
        Assert.Contains("Waived", markdown, StringComparison.Ordinal);
    }
}
