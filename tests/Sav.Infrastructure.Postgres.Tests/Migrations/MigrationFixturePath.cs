namespace Sav.Infrastructure.Postgres.Tests.Migrations;

internal static class MigrationFixturePath
{
    public static string Resolve(params string[] relativeSegments)
    {
        string? dir = AppContext.BaseDirectory;
        while (dir is not null)
        {
            string candidate = Path.Combine(
                new[] { dir, "tests", "fixtures", "migrations" }
                    .Concat(relativeSegments)
                    .ToArray());
            if (File.Exists(candidate))
            {
                return candidate;
            }

            dir = Directory.GetParent(dir)?.FullName;
        }

        throw new InvalidOperationException(
            "Migration fixture not found: " + Path.Combine(relativeSegments));
    }

    public static string Read(params string[] relativeSegments)
    {
        return File.ReadAllText(Resolve(relativeSegments));
    }
}
