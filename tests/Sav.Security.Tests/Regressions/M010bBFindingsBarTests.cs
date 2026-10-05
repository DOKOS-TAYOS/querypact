using System.Text.Json;
using System.Text.RegularExpressions;

namespace Sav.Security.Tests.Regressions;

/// <summary>
/// M010b-B bar lock: MVP-B track must record 0 open Critical and 0 open High
/// (or overflow to M010c-B). After H1 + Medium remediations, skip M010c-B.
/// </summary>
public sealed class M010bBFindingsBarTests
{
    [Fact]
    public void M010b_b_findings_records_zero_open_critical_and_high()
    {
        string path = Path.Combine(
            global::Sav.Security.Tests.SecurityAnalyzeHarness.FindRepoRoot(),
            "docs",
            "security",
            "m010b-b-findings.md");
        Assert.True(File.Exists(path), "Missing findings file: " + path);

        string markdown = File.ReadAllText(path);
        Match match = Regex.Match(
            markdown,
            "```json\\s*(?<json>\\{[\\s\\S]*?\\})\\s*```",
            RegexOptions.CultureInvariant);
        Assert.True(match.Success, "Expected machine-readable JSON block in m010b-b-findings.md");

        using JsonDocument doc = JsonDocument.Parse(match.Groups["json"].Value);
        JsonElement root = doc.RootElement;

        Assert.Equal(1, root.GetProperty("schemaVersion").GetInt32());
        Assert.Equal("MVP-B", root.GetProperty("band").GetString());
        Assert.Equal("M010b-B", root.GetProperty("milestone").GetString());
        Assert.Equal(JsonValueKind.Array, root.GetProperty("openCritical").ValueKind);
        Assert.Equal(0, root.GetProperty("openCritical").GetArrayLength());
        Assert.Equal(JsonValueKind.Array, root.GetProperty("openHigh").ValueKind);
        Assert.Equal(0, root.GetProperty("openHigh").GetArrayLength());
        Assert.True(root.GetProperty("skipM010cB").GetBoolean());
        Assert.Equal(JsonValueKind.Null, root.GetProperty("overflowMilestone").ValueKind);
        Assert.True(root.GetProperty("remediatedThisMilestone").GetArrayLength() >= 1);
    }
}
