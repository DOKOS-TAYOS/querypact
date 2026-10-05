using System.Reflection;
using Sav.Application.Abstractions;
using Sav.Application.Analyze;
using Sav.Domain.Decisions;

namespace Sav.Application.Tests.Analyze;

public sealed class AnalyzeUsesConfigPathResolverPortTests
{
    [Fact]
    public void AnalyzeSqlUseCase_constructor_takes_IConfigPathResolver_not_infra_concrete()
    {
        ConstructorInfo ctor = typeof(AnalyzeSqlUseCase).GetConstructors().Single();
        Type[] parameters = ctor.GetParameters().Select(p => p.ParameterType).ToArray();

        Assert.Contains(typeof(IConfigPathResolver), parameters);
        Assert.DoesNotContain(
            parameters,
            t => t.Name.Contains("ConfigPathResolver", StringComparison.Ordinal) &&
                 t != typeof(IConfigPathResolver));
        Assert.All(
            parameters,
            t => Assert.False(
                t.Namespace?.Contains("Infrastructure", StringComparison.OrdinalIgnoreCase) == true,
                $"Application must not depend on Infra type {t}"));
    }

    [Fact]
    public async Task ExecuteAsync_resolves_policy_path_via_port_only()
    {
        FakePathResolver paths = new();
        AnalyzeSqlUseCase useCase = new(
            new FakeParser(success: true),
            new FakePolicyEngine(PolicyOutcome.Allow),
            new FakePolicyLoader(),
            new FakeContractLoader(),
            paths,
            new RecordingRedactor());

        _ = await useCase.ExecuteAsync(
            new AnalyzeSqlRequest("SELECT 1", "policies/demo.yaml", null),
            CancellationToken.None);

        Assert.Equal(1, paths.ResolveCalls);
        Assert.Equal("policies/demo.yaml", paths.LastRelativePath);
    }
}
