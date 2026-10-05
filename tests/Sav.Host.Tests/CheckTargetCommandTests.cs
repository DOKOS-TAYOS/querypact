using System.CommandLine;
using Sav.Host.Cli;
using Sav.Host.Configuration;

namespace Sav.Host.Tests;

public sealed class CheckTargetCommandTests
{
    [Fact]
    public void Rejects_unconfigured_alias_without_exposing_connection_data()
    {
        RootCommand root = new();
        root.Subcommands.Add(CheckTargetCommand.Create(() => new SavModeOptions()));

        using StringWriter stdout = new();
        using StringWriter stderr = new();
        ParseResult parse = root.Parse(["check-target", "--target", "missing"]);
        int exit = parse.Invoke(new InvocationConfiguration { Output = stdout, Error = stderr });

        Assert.Equal(1, exit);
        Assert.Contains("alias_unknown", stderr.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain("Password=", stderr.ToString(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Rejects_connection_string_instead_of_operator_alias()
    {
        RootCommand root = new();
        root.Subcommands.Add(CheckTargetCommand.Create(() => new SavModeOptions()));

        using StringWriter stdout = new();
        using StringWriter stderr = new();
        ParseResult parse = root.Parse(["check-target", "--target", "Host=example;Password=secret"]);
        int exit = parse.Invoke(new InvocationConfiguration { Output = stdout, Error = stderr });

        Assert.Equal(1, exit);
        Assert.Contains("alias_looks_like_dsn", stderr.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain("secret", stderr.ToString(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Full_mode_preflight_does_not_construct_hmac_dependent_services()
    {
        using StringWriter stdout = new();
        using StringWriter stderr = new();

        int exit = Program.Run(
            ["--mode", "Full", "check-target", "--target", "missing-preflight-alias"],
            stdout,
            stderr);

        Assert.Equal(1, exit);
        Assert.Contains("alias_unknown", stderr.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain("attestation_hmac_key", stderr.ToString(), StringComparison.OrdinalIgnoreCase);
    }
}
