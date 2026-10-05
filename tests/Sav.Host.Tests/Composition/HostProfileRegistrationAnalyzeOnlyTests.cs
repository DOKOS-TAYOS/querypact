using Microsoft.Extensions.DependencyInjection;
using Sav.Application.Abstractions;
using Sav.Application.Analyze;
using Sav.Host.Composition;
using Sav.Host.Configuration;
using Sav.Infrastructure.Config;
using Sav.Infrastructure.Config.Paths;
using Sav.Infrastructure.Config.Policies;
using Sav.Infrastructure.Postgres.Parsing;
using Sav.Infrastructure.Postgres.Redaction;

namespace Sav.Host.Tests.Composition;

public sealed class HostProfileRegistrationAnalyzeOnlyTests
{
    [Fact]
    public void AnalyzeOnly_registers_profile_services()
    {
        using ServiceProvider sp = Program.BuildServiceProvider(
            DiProfile.AnalyzeOnly,
            options: new SavModeOptions { Mode = DiProfile.AnalyzeOnly, ConfigRoot = Path.GetTempPath() });

        Assert.IsType<AnalyzeSqlUseCase>(sp.GetRequiredService<IAnalyzeSqlUseCase>());
        Assert.IsType<LibPgQuerySqlParser>(sp.GetRequiredService<ISqlParser>());
        Assert.IsType<YamlPolicyEngine>(sp.GetRequiredService<IPolicyEngine>());
        Assert.IsType<YamlPolicyLoader>(sp.GetRequiredService<IPolicyLoader>());
        Assert.IsType<YamlContractLoader>(sp.GetRequiredService<IContractLoader>());
        Assert.IsType<ConfigPathResolver>(sp.GetRequiredService<IConfigPathResolver>());
        Assert.IsType<PostgresErrorRedactor>(sp.GetRequiredService<IRedactor>());
    }
}
