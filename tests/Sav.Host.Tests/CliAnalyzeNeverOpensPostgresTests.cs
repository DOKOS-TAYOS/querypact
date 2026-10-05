using System.Reflection;
using Microsoft.Extensions.DependencyInjection;
using Sav.Application.Abstractions;
using Sav.Application.Analyze;
using Sav.Host.Composition;
using Sav.Host.Tests.E2E;

namespace Sav.Host.Tests;

/// <summary>
/// Analyze path must never open PostgreSQL (M009a / M010a-A-corpus-w2).
/// </summary>
public sealed class CliAnalyzeNeverOpensPostgresTests : SavEnvTestBase
{
    [Fact]
    public void AnalyzeSqlUseCase_ctor_has_no_session_or_connection_dependencies()
    {
        ConstructorInfo ctor = typeof(AnalyzeSqlUseCase).GetConstructors().Single();
        Type[] forbidden =
        [
            typeof(IReadOnlySessionFactory),
            typeof(IReadOnlySession),
            typeof(IPlanProvider),
            typeof(ICatalogResolver),
            typeof(ITargetAliasResolver),
        ];

        foreach (ParameterInfo parameter in ctor.GetParameters())
        {
            Assert.DoesNotContain(parameter.ParameterType, forbidden);
            Assert.DoesNotContain("Npgsql", parameter.ParameterType.FullName ?? string.Empty, StringComparison.Ordinal);
            Assert.DoesNotContain("Connection", parameter.ParameterType.Name, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void AnalyzeOnly_di_does_not_resolve_session_factory()
    {
        using E2EHostHarness.TempWorkspace workspace = E2EHostHarness.CreateWorkspace(includeContract: false);
        using ServiceProvider sp = E2EHostHarness.BuildAnalyzeOnly(workspace);

        Assert.NotNull(sp.GetService<IAnalyzeSqlUseCase>());
        Assert.Null(sp.GetService<IReadOnlySessionFactory>());
        Assert.Null(sp.GetService<IPlanProvider>());
        Assert.Null(sp.GetService<ICatalogResolver>());
    }

    [Fact]
    public void Analyze_cli_completes_without_targets_or_dsn_env()
    {
        using E2EHostHarness.TempWorkspace workspace = E2EHostHarness.CreateWorkspace(includeContract: false);
        using IDisposable env = E2EHostHarness.ConfigureCliEnvironment(workspace, DiProfile.AnalyzeOnly);

        using StringWriter stdout = new();
        using StringWriter stderr = new();
        int exit = Program.Run(
            [
                "--mode", "AnalyzeOnly",
                "analyze",
                "--sql", "SELECT 1",
                "--policy", workspace.PolicyRelativePath,
            ],
            stdout,
            stderr);

        Assert.Equal(0, exit);
        Assert.True(string.IsNullOrWhiteSpace(stderr.ToString()));
        Assert.Contains("\"outcome\"", stdout.ToString(), StringComparison.OrdinalIgnoreCase);
        E2EHostHarness.AssertNoConnectionStringLeak(stdout.ToString());
    }
}
