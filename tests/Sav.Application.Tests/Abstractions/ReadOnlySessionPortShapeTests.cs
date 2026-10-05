using System.Reflection;
using Sav.Application.Abstractions;
using Sav.Domain.Targets;

namespace Sav.Application.Tests.Abstractions;

public sealed class ReadOnlySessionPortShapeTests
{
    [Fact]
    public void Factory_returns_typed_IReadOnlySession_not_bare_IAsyncDisposable()
    {
        MethodInfo method = typeof(IReadOnlySessionFactory)
            .GetMethod(nameof(IReadOnlySessionFactory.OpenReadOnlySessionAsync))!;
        Assert.Equal(typeof(Task<IReadOnlySession>), method.ReturnType);
        Assert.Contains(typeof(IAsyncDisposable), typeof(IReadOnlySession).GetInterfaces());
        Assert.NotNull(typeof(IReadOnlySession).GetMethod(nameof(IReadOnlySession.ExecuteAsync)));
        Assert.NotNull(typeof(IReadOnlySession).GetMethod(nameof(IReadOnlySession.ExecuteReaderAsync)));
    }

    [Fact]
    public void PropertyEvaluationRequest_includes_optional_session()
    {
        PropertyInfo? session = typeof(PropertyEvaluationRequest).GetProperty("Session");
        Assert.NotNull(session);
        Assert.Equal(typeof(IReadOnlySession), session!.PropertyType);
    }

    [Fact]
    public void OpenReadOnlySessionAsync_takes_target_alias_and_cancellation()
    {
        ParameterInfo[] parameters = typeof(IReadOnlySessionFactory)
            .GetMethod(nameof(IReadOnlySessionFactory.OpenReadOnlySessionAsync))!
            .GetParameters();
        Assert.Equal(2, parameters.Length);
        Assert.Equal(typeof(TargetAlias), parameters[0].ParameterType);
        Assert.Equal(typeof(CancellationToken), parameters[1].ParameterType);
    }
}
