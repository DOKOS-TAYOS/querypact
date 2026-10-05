using System.Collections.Immutable;
using System.Globalization;
using System.Text.Json;

namespace Sav.Security.Tests.Benchmark;

internal enum SecurityBenchmarkSeverity
{
    Critical,
    High,
    Medium,
    Low,
}

internal sealed record SecurityBenchmarkCase(
    string Id,
    int Wave,
    SecurityBenchmarkSeverity Severity,
    string Category,
    string Title,
    string OwnerTest,
    string ExpectedOutcome);

internal sealed record SecurityBenchmarkCorpus(
    int SchemaVersion,
    string Band,
    ImmutableArray<SecurityBenchmarkCase> Cases)
{
    public static SecurityBenchmarkCorpus LoadMvpA()
    {
        string path = Path.Combine(
            global::Sav.Security.Tests.SecurityAnalyzeHarness.FindRepoRoot(),
            "tests",
            "fixtures",
            "security",
            "benchmark-corpus-mvp-a.json");
        return Parse(File.ReadAllText(path));
    }

    public static SecurityBenchmarkCorpus LoadMvpB()
    {
        string path = Path.Combine(
            global::Sav.Security.Tests.SecurityAnalyzeHarness.FindRepoRoot(),
            "tests",
            "fixtures",
            "security",
            "benchmark-corpus-mvp-b.json");
        return Parse(File.ReadAllText(path));
    }

    public static SecurityBenchmarkCorpus Parse(string json)
    {
        using JsonDocument doc = JsonDocument.Parse(json);
        JsonElement root = doc.RootElement;
        if (root.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidOperationException("Benchmark corpus root must be an object.");
        }

        if (!root.TryGetProperty("schemaVersion", out JsonElement schemaVersionEl)
            || schemaVersionEl.ValueKind != JsonValueKind.Number
            || schemaVersionEl.GetInt32() != 1)
        {
            throw new InvalidOperationException("schemaVersion must be the integer 1.");
        }

        if (!root.TryGetProperty("band", out JsonElement bandEl)
            || bandEl.ValueKind != JsonValueKind.String
            || bandEl.GetString() is not string band
            || band.Length == 0)
        {
            throw new InvalidOperationException("band must be a non-empty string.");
        }

        if (!root.TryGetProperty("cases", out JsonElement casesEl)
            || casesEl.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidOperationException("cases must be an array.");
        }

        ImmutableArray<SecurityBenchmarkCase>.Builder builder = ImmutableArray.CreateBuilder<SecurityBenchmarkCase>();
        HashSet<string> ids = new(StringComparer.Ordinal);
        foreach (JsonElement item in casesEl.EnumerateArray())
        {
            SecurityBenchmarkCase parsed = ParseCase(item);
            if (!ids.Add(parsed.Id))
            {
                throw new InvalidOperationException("Duplicate case id: " + parsed.Id);
            }

            builder.Add(parsed);
        }

        return new SecurityBenchmarkCorpus(schemaVersionEl.GetInt32(), band, builder.ToImmutable());
    }

    private static SecurityBenchmarkCase ParseCase(JsonElement item)
    {
        string id = RequireString(item, "id");
        try
        {
            int wave = RequireInt(item, "wave");
            if (wave is < 1 or > 3)
            {
                throw new InvalidOperationException("wave must be 1, 2, or 3.");
            }

            string severityRaw = RequireString(item, "severity");
            if (!Enum.TryParse(severityRaw, ignoreCase: false, out SecurityBenchmarkSeverity severity)
                || !string.Equals(severity.ToString(), severityRaw, StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    "severity must be Critical, High, Medium, or Low (exact casing).");
            }

            string category = RequireString(item, "category");
            string title = RequireString(item, "title");
            string ownerTest = RequireString(item, "ownerTest");
            string expectedOutcome = RequireString(item, "expectedOutcome");

            return new SecurityBenchmarkCase(
                id,
                wave,
                severity,
                category,
                title,
                ownerTest,
                expectedOutcome);
        }
        catch (InvalidOperationException ex)
        {
            throw new InvalidOperationException(
                string.Format(CultureInfo.InvariantCulture, "Invalid case '{0}': {1}", id, ex.Message),
                ex);
        }
    }

    private static string RequireString(JsonElement item, string name)
    {
        if (!item.TryGetProperty(name, out JsonElement el)
            || el.ValueKind != JsonValueKind.String
            || el.GetString() is not string value
            || value.Length == 0)
        {
            throw new InvalidOperationException("missing or empty required string field '" + name + "'.");
        }

        return value;
    }

    private static int RequireInt(JsonElement item, string name)
    {
        if (!item.TryGetProperty(name, out JsonElement el) || el.ValueKind != JsonValueKind.Number)
        {
            throw new InvalidOperationException("missing required integer field '" + name + "'.");
        }

        return el.GetInt32();
    }
}

internal sealed record SecurityBenchmarkRunResult(
    bool Passed,
    int CaseCount,
    int OpenCriticalOrHighFailures);

internal static class SecurityBenchmarkHarness
{
    /// <summary>
    /// Validates corpus identity and enumerates cases. Empty corpus is an accepted green run
    /// (M010a-A-harness). Later waves / M010a-B assert case IDs and execute owner tests.
    /// </summary>
    public static SecurityBenchmarkRunResult Run(SecurityBenchmarkCorpus corpus)
    {
        if (corpus.SchemaVersion != 1)
        {
            throw new InvalidOperationException("Unsupported schemaVersion.");
        }

        if (!string.Equals(corpus.Band, "MVP-A", StringComparison.Ordinal)
            && !string.Equals(corpus.Band, "MVP-B", StringComparison.Ordinal))
        {
            throw new InvalidOperationException("Harness runner requires band MVP-A or MVP-B.");
        }

        // Harness: case ID / owner execution owned by wave / M010a-B tests.
        // Zero open Critical/High failures here means the corpus loaded and enumerated cleanly.
        return new SecurityBenchmarkRunResult(
            Passed: true,
            CaseCount: corpus.Cases.Length,
            OpenCriticalOrHighFailures: 0);
    }
}

internal static class SecurityBenchmarkOwnerArtifacts
{
    public static bool OwnerTestArtifactExists(string ownerTest)
    {
        // Prefer type resolution in loaded assemblies; fall back to source-path probe for other test projects.
        string typeName = ownerTest.Contains('.', StringComparison.Ordinal)
            ? ownerTest[..ownerTest.LastIndexOf('.')]
            : ownerTest;

        foreach (System.Reflection.Assembly assembly in AppDomain.CurrentDomain.GetAssemblies())
        {
            try
            {
                if (assembly.GetType(typeName, throwOnError: false, ignoreCase: false) is not null)
                {
                    return true;
                }
            }
            catch (System.Reflection.ReflectionTypeLoadException)
            {
            }
        }

        string repo = SecurityAnalyzeHarness.FindRepoRoot();
        string[] parts = ownerTest.Split('.');
        if (parts.Length < 2)
        {
            return false;
        }

        string typeSimple = parts.Reverse().FirstOrDefault(p => p.EndsWith("Tests", StringComparison.Ordinal))
            ?? parts[^1];

        return Directory
            .EnumerateFiles(Path.Combine(repo, "tests"), typeSimple + ".cs", SearchOption.AllDirectories)
            .Any();
    }
}
