using System.Text.Json;
using Sav.Application.Abstractions;
using Sav.Application.Analyze;
using Sav.Domain.Policies;
using Sav.Infrastructure.Config;
using Sav.Infrastructure.Config.Paths;
using Sav.Infrastructure.Config.Policies;
using Sav.Infrastructure.Postgres.Parsing;

namespace Sav.Security.Tests;

internal static class SecurityAnalyzeHarness
{
    public static AnalyzeSqlUseCase CreateUseCase(string configRoot)
    {
        ConfigPathResolver paths = new(new ConfigRootOptions { ConfigRoot = configRoot });
        return new AnalyzeSqlUseCase(
            parser: new LibPgQuerySqlParser(),
            policyEngine: new YamlPolicyEngine(),
            policyLoader: new YamlPolicyLoader(),
            contractLoader: new YamlContractLoader(),
            paths: paths,
            redactor: new IdentityRedactor());
    }

    public static string FindRepoRoot()
    {
        DirectoryInfo? dir = new(AppContext.BaseDirectory);
        while (dir is not null)
        {
            if (File.Exists(Path.Combine(dir.FullName, "QueryPact.sln")))
            {
                return dir.FullName;
            }

            dir = dir.Parent;
        }

        throw new InvalidOperationException("QueryPact.sln not found.");
    }

    public static string CorpusSql(string id)
    {
        string path = Path.Combine(FindRepoRoot(), "tests", "fixtures", "sql", "adversarial-corpus.json");
        using FileStream stream = File.OpenRead(path);
        using JsonDocument doc = JsonDocument.Parse(stream);
        foreach (JsonElement item in doc.RootElement.GetProperty("cases").EnumerateArray())
        {
            if (string.Equals(item.GetProperty("id").GetString(), id, StringComparison.Ordinal))
            {
                return item.GetProperty("sql").GetString()
                    ?? throw new InvalidOperationException("Missing sql for " + id);
            }
        }

        throw new InvalidOperationException("Corpus case not found: " + id);
    }

    public static TempPolicyRoot CreatePolicyRoot(string fixtureFileName)
    {
        string repoRoot = FindRepoRoot();
        string source = Path.Combine(repoRoot, "tests", "fixtures", "policies", fixtureFileName);
        string root = Path.Combine(Path.GetTempPath(), "sav-sec-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        string destName = "policy.yaml";
        File.Copy(source, Path.Combine(root, destName), overwrite: true);
        return new TempPolicyRoot(root, destName);
    }

    internal sealed class TempPolicyRoot : IDisposable
    {
        public TempPolicyRoot(string path, string policyRelativePath)
        {
            Path = path;
            PolicyRelativePath = policyRelativePath;
        }

        public string Path { get; }

        public string PolicyRelativePath { get; }

        public void Dispose()
        {
            try
            {
                if (Directory.Exists(Path))
                {
                    Directory.Delete(Path, recursive: true);
                }
            }
            catch (IOException)
            {
            }
        }
    }

    private sealed class IdentityRedactor : IRedactor
    {
        public string RedactText(string value, DisclosureProfile profile) => value;

        public T RedactObject<T>(T value, DisclosureProfile profile) => value;
    }
}
