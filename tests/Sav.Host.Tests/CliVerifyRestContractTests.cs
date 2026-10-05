using Sav.Infrastructure.Storage.Attestations;

namespace Sav.Host.Tests;

public sealed class CliVerifyRestContractTests : SavEnvTestBase
{
    [Fact]
    public void Verify_equivalence_and_migration_help_exist_under_Full()
    {
        using IDisposable key = EnvScope.Set(
            AttestationHmacKeyDecoder.EnvironmentVariableName,
            "base64:" + Convert.ToBase64String(Enumerable.Repeat((byte)0x47, 32).ToArray()));

        using StringWriter eqOut = new();
        using StringWriter eqErr = new();
        Assert.Equal(0, Program.Run(["--mode", "Full", "verify-equivalence", "--help"], eqOut, eqErr));
        string eqHelp = eqOut.ToString();
        Assert.Contains("--left-sql", eqHelp, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("--right-sql", eqHelp, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("explain-analyze", eqHelp, StringComparison.OrdinalIgnoreCase);

        using StringWriter migOut = new();
        using StringWriter migErr = new();
        Assert.Equal(0, Program.Run(["--mode", "Full", "verify-migration", "--help"], migOut, migErr));
        string migHelp = migOut.ToString();
        Assert.Contains("--migration-sql", migHelp, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("--migration-path", migHelp, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("--base-schema", migHelp, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("explain-analyze", migHelp, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Verify_migration_rejects_both_sql_and_path()
    {
        using IDisposable key = EnvScope.Set(
            AttestationHmacKeyDecoder.EnvironmentVariableName,
            "base64:" + Convert.ToBase64String(Enumerable.Repeat((byte)0x48, 32).ToArray()));
        using IDisposable store = EnvScope.Set(
            Configuration.SavModeOptions.AttestationStoreRootEnvironmentVariable,
            Path.Combine(Path.GetTempPath(), "sav-mig-" + Guid.NewGuid().ToString("N")));

        using StringWriter stdout = new();
        using StringWriter stderr = new();
        int exit = Program.Run(
            [
                "--mode", "Full",
                "verify-migration",
                "--migration-sql", "SELECT 1",
                "--migration-path", "m.sql",
                "--base-schema", "base.sql",
                "--policy", "p.yaml",
                "--contract", "c.yaml",
            ],
            stdout,
            stderr);

        Assert.NotEqual(0, exit);
        Assert.Contains("unsupported_construct", stderr.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void Verify_migration_rejects_neither_sql_nor_path()
    {
        using IDisposable key = EnvScope.Set(
            AttestationHmacKeyDecoder.EnvironmentVariableName,
            "base64:" + Convert.ToBase64String(Enumerable.Repeat((byte)0x49, 32).ToArray()));
        using IDisposable store = EnvScope.Set(
            Configuration.SavModeOptions.AttestationStoreRootEnvironmentVariable,
            Path.Combine(Path.GetTempPath(), "sav-mig-neither-" + Guid.NewGuid().ToString("N")));

        using StringWriter stdout = new();
        using StringWriter stderr = new();
        int exit = Program.Run(
            [
                "--mode", "Full",
                "verify-migration",
                "--base-schema", "base.sql",
                "--policy", "p.yaml",
                "--contract", "c.yaml",
            ],
            stdout,
            stderr);

        Assert.NotEqual(0, exit);
        Assert.Contains("unsupported_construct", stderr.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void Equivalence_and_migration_help_have_no_dsn_option()
    {
        using IDisposable key = EnvScope.Set(
            AttestationHmacKeyDecoder.EnvironmentVariableName,
            "base64:" + Convert.ToBase64String(Enumerable.Repeat((byte)0x4A, 32).ToArray()));

        using StringWriter eqOut = new();
        using StringWriter eqErr = new();
        Assert.Equal(0, Program.Run(["--mode", "Full", "verify-equivalence", "--help"], eqOut, eqErr));
        string eqHelp = eqOut.ToString();
        Assert.DoesNotContain("--dsn", eqHelp, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("connection string", eqHelp, StringComparison.OrdinalIgnoreCase);

        using StringWriter migOut = new();
        using StringWriter migErr = new();
        Assert.Equal(0, Program.Run(["--mode", "Full", "verify-migration", "--help"], migOut, migErr));
        string migHelp = migOut.ToString();
        Assert.DoesNotContain("--dsn", migHelp, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("connection string", migHelp, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void AnalyzeOnly_excludes_equivalence_and_migration()
    {
        using StringWriter stdout = new();
        using StringWriter stderr = new();
        Assert.Equal(0, Program.Run(["--mode", "AnalyzeOnly", "--help"], stdout, stderr));
        string help = stdout.ToString();
        Assert.DoesNotContain("verify-equivalence", help, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("verify-migration", help, StringComparison.OrdinalIgnoreCase);
    }
}
