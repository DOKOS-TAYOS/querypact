namespace Sav.Infrastructure.Config.Paths;

/// <summary>
/// Operator options for <c>Sav:ConfigRoot</c> (absolute directory; default = process CWD).
/// </summary>
public sealed class ConfigRootOptions
{
    /// <summary>
    /// Absolute config root directory. Empty/whitespace means <see cref="Environment.CurrentDirectory"/> at construction.
    /// </summary>
    public string ConfigRoot { get; set; } = string.Empty;
}
