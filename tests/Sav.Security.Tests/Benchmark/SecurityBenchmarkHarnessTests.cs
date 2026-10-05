using System.Text.Json;

namespace Sav.Security.Tests.Benchmark;

public sealed class SecurityBenchmarkHarnessTests
{
    [Fact]
    public void Mvp_a_corpus_loads_validates_and_runs_green()
    {
        SecurityBenchmarkCorpus corpus = SecurityBenchmarkCorpus.LoadMvpA();

        Assert.Equal(1, corpus.SchemaVersion);
        Assert.Equal("MVP-A", corpus.Band);

        SecurityBenchmarkRunResult result = SecurityBenchmarkHarness.Run(corpus);

        Assert.True(result.Passed);
        Assert.Equal(corpus.Cases.Length, result.CaseCount);
        Assert.Equal(0, result.OpenCriticalOrHighFailures);
    }

    [Fact]
    public void Empty_corpus_json_is_accepted_by_schema()
    {
        const string json = """
            {
              "schemaVersion": 1,
              "band": "MVP-A",
              "cases": []
            }
            """;

        SecurityBenchmarkCorpus corpus = SecurityBenchmarkCorpus.Parse(json);
        Assert.Empty(corpus.Cases);
        SecurityBenchmarkRunResult result = SecurityBenchmarkHarness.Run(corpus);
        Assert.True(result.Passed);
        Assert.Equal(0, result.CaseCount);
    }

    [Fact]
    public void Schema_rejects_case_missing_required_fields()
    {
        const string json = """
            {
              "schemaVersion": 1,
              "band": "MVP-A",
              "cases": [
                { "id": "incomplete" }
              ]
            }
            """;

        InvalidOperationException ex = Assert.Throws<InvalidOperationException>(
            () => SecurityBenchmarkCorpus.Parse(json));

        Assert.Contains("incomplete", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Schema_accepts_fully_populated_case_record()
    {
        const string json = """
            {
              "schemaVersion": 1,
              "band": "MVP-A",
              "cases": [
                {
                  "id": "example_case",
                  "wave": 1,
                  "severity": "High",
                  "category": "bypass",
                  "title": "Example case for schema validation",
                  "ownerTest": "Sav.Security.Tests.Benchmark.ExampleTests.Example",
                  "expectedOutcome": "deny"
                }
              ]
            }
            """;

        SecurityBenchmarkCorpus corpus = SecurityBenchmarkCorpus.Parse(json);

        Assert.Single(corpus.Cases);
        SecurityBenchmarkCase c = corpus.Cases[0];
        Assert.Equal("example_case", c.Id);
        Assert.Equal(1, c.Wave);
        Assert.Equal(SecurityBenchmarkSeverity.High, c.Severity);
        Assert.Equal("bypass", c.Category);
        Assert.Equal("deny", c.ExpectedOutcome);
    }

    [Fact]
    public void Fixture_file_matches_documented_root_schema()
    {
        string path = Path.Combine(
            global::Sav.Security.Tests.SecurityAnalyzeHarness.FindRepoRoot(),
            "tests",
            "fixtures",
            "security",
            "benchmark-corpus-mvp-a.json");

        Assert.True(File.Exists(path), "Missing fixture: " + path);

        using JsonDocument doc = JsonDocument.Parse(File.ReadAllText(path));
        JsonElement root = doc.RootElement;
        Assert.Equal(JsonValueKind.Object, root.ValueKind);
        Assert.Equal(1, root.GetProperty("schemaVersion").GetInt32());
        Assert.Equal("MVP-A", root.GetProperty("band").GetString());
        Assert.Equal(JsonValueKind.Array, root.GetProperty("cases").ValueKind);
    }
}
