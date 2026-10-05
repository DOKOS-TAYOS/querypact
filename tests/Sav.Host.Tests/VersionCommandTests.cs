using System.Globalization;

namespace Sav.Host.Tests;

public sealed class VersionCommandTests
{
    [Fact]
    public void Version_prints_non_empty_string_without_connection_string_patterns()
    {
        using StringWriter stdout = new();
        using StringWriter stderr = new();

        int exitCode = Program.Run(["--version"], stdout, stderr);

        Assert.Equal(0, exitCode);
        string output = stdout.ToString();
        Assert.False(string.IsNullOrWhiteSpace(output));
        AssertNoConnectionStringLeak(output);
        Assert.True(string.IsNullOrWhiteSpace(stderr.ToString()));
    }

    [Fact]
    public void Help_prints_non_empty_help_and_exits_zero()
    {
        using StringWriter stdout = new();
        using StringWriter stderr = new();

        int exitCode = Program.Run(["--help"], stdout, stderr);

        Assert.Equal(0, exitCode);
        string output = stdout.ToString();
        Assert.False(string.IsNullOrWhiteSpace(output));
        Assert.Contains("--version", output, StringComparison.OrdinalIgnoreCase);
        AssertNoConnectionStringLeak(output);
        AssertNoConnectionStringLeak(stderr.ToString());
        Assert.True(string.IsNullOrWhiteSpace(stderr.ToString()));
    }

    [Fact]
    public void Help_is_english_under_spanish_ui_culture_with_clean_stderr()
    {
        CultureInfo? priorUi = CultureInfo.CurrentUICulture;
        CultureInfo? priorCulture = CultureInfo.CurrentCulture;
        CultureInfo? priorDefaultUi = CultureInfo.DefaultThreadCurrentUICulture;
        CultureInfo? priorDefaultCulture = CultureInfo.DefaultThreadCurrentCulture;

        try
        {
            CultureInfo spanish = CultureInfo.GetCultureInfo("es-ES");
            CultureInfo.CurrentUICulture = spanish;
            CultureInfo.CurrentCulture = spanish;
            CultureInfo.DefaultThreadCurrentUICulture = spanish;
            CultureInfo.DefaultThreadCurrentCulture = spanish;

            using StringWriter stdout = new();
            using StringWriter stderr = new();

            int exitCode = Program.Run(["--help"], stdout, stderr);

            Assert.Equal(0, exitCode);
            string output = stdout.ToString();
            Assert.Contains("Usage:", output, StringComparison.Ordinal);
            Assert.Contains("Show help", output, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("Uso:", output, StringComparison.Ordinal);
            Assert.DoesNotContain("Mostrar ayuda", output, StringComparison.OrdinalIgnoreCase);
            AssertNoConnectionStringLeak(output);
            AssertNoConnectionStringLeak(stderr.ToString());
            Assert.True(string.IsNullOrWhiteSpace(stderr.ToString()));
        }
        finally
        {
            CultureInfo.CurrentUICulture = priorUi;
            CultureInfo.CurrentCulture = priorCulture;
            CultureInfo.DefaultThreadCurrentUICulture = priorDefaultUi;
            CultureInfo.DefaultThreadCurrentCulture = priorDefaultCulture;
        }
    }

    private static void AssertNoConnectionStringLeak(string output)
    {
        string[] patterns =
        [
            "Host=",
            "Password=",
            "Username=",
            "User ID=",
            "Connection String",
            "postgres://",
            "postgresql://",
        ];

        foreach (string pattern in patterns)
        {
            Assert.DoesNotContain(pattern, output, StringComparison.OrdinalIgnoreCase);
        }
    }
}
