namespace Sav.Infrastructure.Config.Tests;

internal static class FixturePath
{
    public static string Resolve(params string[] relativeSegments)
    {
        string? dir = AppContext.BaseDirectory;
        while (dir is not null)
        {
            string candidate = Path.Combine(new[] { dir, "tests", "fixtures" }.Concat(relativeSegments).ToArray());
            if (File.Exists(candidate))
            {
                return candidate;
            }

            dir = Directory.GetParent(dir)?.FullName;
        }

        throw new InvalidOperationException(
            "Fixture not found: " + Path.Combine(relativeSegments));
    }
}
