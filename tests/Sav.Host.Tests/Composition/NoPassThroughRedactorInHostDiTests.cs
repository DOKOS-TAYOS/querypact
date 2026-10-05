using Microsoft.Extensions.DependencyInjection;
using Sav.Application.Abstractions;
using Sav.Host.Composition;
using Sav.Host.Configuration;
using Sav.Infrastructure.Postgres.Redaction;

namespace Sav.Host.Tests.Composition;

public sealed class NoPassThroughRedactorInHostDiTests
{
    [Fact]
    public void AnalyzeOnly_IRedactor_is_not_PassThrough_and_has_no_Extensions_types()
    {
        using ServiceProvider sp = Program.BuildServiceProvider(
            DiProfile.AnalyzeOnly,
            options: new SavModeOptions { Mode = DiProfile.AnalyzeOnly, ConfigRoot = Path.GetTempPath() });

        IRedactor redactor = sp.GetRequiredService<IRedactor>();
        Assert.IsType<PostgresErrorRedactor>(redactor);
        Assert.DoesNotContain("PassThrough", redactor.GetType().Name, StringComparison.Ordinal);
        Assert.DoesNotContain("Extensions", redactor.GetType().FullName ?? string.Empty, StringComparison.Ordinal);

        string hostAsm = typeof(Program).Assembly.FullName ?? string.Empty;
        Assert.DoesNotContain("Extensions", hostAsm, StringComparison.Ordinal);
    }
}
