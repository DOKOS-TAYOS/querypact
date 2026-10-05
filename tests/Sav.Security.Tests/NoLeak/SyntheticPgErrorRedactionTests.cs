using System.Text.Json;
using Sav.Application.Abstractions;
using Sav.Domain.Policies;
using Sav.Infrastructure.Postgres.Redaction;

namespace Sav.Security.Tests.NoLeak;

public sealed class SyntheticPgErrorRedactionTests
{
    private const string Canary = "CANARY_LITERAL_do_not_egress@example.invalid";

    private static readonly DisclosureProfile Strict = DisclosureProfileMerge.StrictDefaults();

    [Fact]
    public void All_synthetic_pg_error_fixtures_are_redacted()
    {
        string path = FindFixturePath();
        string json = File.ReadAllText(path);
        using JsonDocument doc = JsonDocument.Parse(json);
        Assert.True(doc.RootElement.GetArrayLength() >= 5);

        IRedactor redactor = new PostgresErrorRedactor(new StrictRedactor());

        foreach (JsonElement item in doc.RootElement.EnumerateArray())
        {
            string id = item.GetProperty("id").GetString() ?? "(missing-id)";
            string message = item.GetProperty("message").GetString() ?? string.Empty;
            Assert.False(string.IsNullOrWhiteSpace(message), id);

            string redacted = redactor.RedactText(message, Strict);

            Assert.DoesNotContain(Canary, redacted, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("super-secret-password", redacted, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("postgresql://", redacted, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("123456", redacted, StringComparison.Ordinal);
            Assert.DoesNotContain("at Npgsql", redacted, StringComparison.Ordinal);
            Assert.DoesNotContain("at System.Runtime", redacted, StringComparison.Ordinal);
            Assert.Contains(StrictRedactor.RedactedToken, redacted, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void Fixture_file_requires_no_docker_or_live_alias()
    {
        string path = FindFixturePath();
        Assert.True(File.Exists(path));
        Assert.Contains("synthetic-pg-errors.json", path, StringComparison.Ordinal);
    }

    private static string FindFixturePath()
    {
        DirectoryInfo? cursor = new(AppContext.BaseDirectory);
        while (cursor is not null)
        {
            string candidate = Path.Combine(
                cursor.FullName,
                "tests",
                "fixtures",
                "redaction",
                "synthetic-pg-errors.json");
            if (File.Exists(candidate))
            {
                return candidate;
            }

            cursor = cursor.Parent;
        }

        throw new InvalidOperationException("synthetic-pg-errors.json fixture not found.");
    }
}
