using Sav.Host.Composition;

namespace Sav.Host.Tests;

internal static class EnvScope
{
    public static IDisposable Set(string name, string? value)
    {
        string? prior = Environment.GetEnvironmentVariable(name);
        Environment.SetEnvironmentVariable(name, value);
        return new Restore(name, prior);
    }

    public static IDisposable UseAnalyzeOnly() =>
        Set(Configuration.SavModeOptions.ModeEnvironmentVariable, nameof(DiProfile.AnalyzeOnly));

    public static IDisposable UseFull() =>
        Set(Configuration.SavModeOptions.ModeEnvironmentVariable, nameof(DiProfile.Full));

    private sealed class Restore(string name, string? prior) : IDisposable
    {
        public void Dispose() => Environment.SetEnvironmentVariable(name, prior);
    }
}
