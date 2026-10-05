namespace Sav.Infrastructure.Postgres.Targets;

/// <summary>
/// Alias → DSN environment variable name (Host maps config into this).
/// Holds names only, not DSN values.
/// </summary>
public sealed class TargetsBindingOptions
{
    public IReadOnlyDictionary<string, string> AliasToDsnEnvVar { get; }

    public TargetsBindingOptions(IReadOnlyDictionary<string, string> aliasToDsnEnvVar)
    {
        ArgumentNullException.ThrowIfNull(aliasToDsnEnvVar);
        AliasToDsnEnvVar = new Dictionary<string, string>(aliasToDsnEnvVar, StringComparer.OrdinalIgnoreCase);
    }
}
