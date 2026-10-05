using System.CommandLine;
using Microsoft.Extensions.DependencyInjection;
using Sav.Application.Abstractions;
using Sav.Application.Migrations;
using Sav.Application.Verify;
using Sav.Domain.Errors;
using Sav.Host.Cli;

namespace Sav.Host.Tests;

/// <summary>
/// M010b-B M4: CLI SavException egress must redact like MCP (no raw canary in stderr).
/// </summary>
public sealed class CliSavExceptionRedactionTests
{
    private const string Canary = "CANARY_LITERAL_do_not_egress@example.invalid";

    [Fact]
    public void Verify_equivalence_cli_redacts_sav_exception_canary_from_stderr()
    {
        ServiceCollection services = new();
        services.AddSingleton<IVerifyEquivalenceUseCase>(new ThrowingEquivalenceUseCase());
        using ServiceProvider sp = services.BuildServiceProvider();

        RootCommand root = new();
        root.Subcommands.Add(VerifyEquivalenceCommand.Create(() => sp));

        using StringWriter stdout = new();
        using StringWriter stderr = new();
        ParseResult parse = root.Parse(
        [
            "verify-equivalence",
            "--left-sql", "SELECT 1",
            "--right-sql", "SELECT 2",
            "--target", "demo",
            "--policy", "p.yaml",
            "--contract", "c.yaml",
        ]);
        int exit = parse.Invoke(new InvocationConfiguration { Output = stdout, Error = stderr });

        Assert.Equal(1, exit);
        string err = stderr.ToString();
        Assert.Contains("alias_unknown", err, StringComparison.Ordinal);
        Assert.DoesNotContain(Canary, err, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Verify_migration_cli_redacts_sav_exception_canary_from_stderr()
    {
        ServiceCollection services = new();
        services.AddSingleton<IVerifyMigrationUseCase>(new ThrowingMigrationUseCase());
        using ServiceProvider sp = services.BuildServiceProvider();

        RootCommand root = new();
        root.Subcommands.Add(VerifyMigrationCommand.Create(() => sp));

        using StringWriter stdout = new();
        using StringWriter stderr = new();
        ParseResult parse = root.Parse(
        [
            "verify-migration",
            "--migration-sql", "SELECT 1",
            "--base-schema", "base.sql",
            "--policy", "p.yaml",
            "--contract", "c.yaml",
        ]);
        int exit = parse.Invoke(new InvocationConfiguration { Output = stdout, Error = stderr });

        Assert.Equal(1, exit);
        string err = stderr.ToString();
        Assert.Contains("alias_unknown", err, StringComparison.Ordinal);
        Assert.DoesNotContain(Canary, err, StringComparison.OrdinalIgnoreCase);
    }

    private sealed class ThrowingEquivalenceUseCase : IVerifyEquivalenceUseCase
    {
        public Task<VerifyEquivalenceResponse> ExecuteAsync(
            VerifyEquivalenceRequest request,
            CancellationToken cancellationToken) =>
            throw new SavException(
                SavErrorCode.AliasUnknown,
                "alias_unknown: boom " + Canary);
    }

    private sealed class ThrowingMigrationUseCase : IVerifyMigrationUseCase
    {
        public Task<VerifyMigrationResponse> ExecuteAsync(
            VerifyMigrationRequest request,
            CancellationToken cancellationToken) =>
            throw new SavException(
                SavErrorCode.AliasUnknown,
                "alias_unknown: boom " + Canary);
    }
}
