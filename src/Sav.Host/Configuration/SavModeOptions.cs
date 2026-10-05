using System.Text.Json;
using System.Text.RegularExpressions;
using Sav.Domain.Errors;
using Sav.Host.Composition;
using Sav.Infrastructure.Config.Paths;

namespace Sav.Host.Configuration;

/// <summary>
/// Host mode and operator path roots. Does not hold DSN values.
/// </summary>
public sealed class SavModeOptions
{
    public const string ModeEnvironmentVariable = "SAV_MODE";
    public const string ConfigRootEnvironmentVariable = "SAV_CONFIG_ROOT";
    public const string AttestationStoreRootEnvironmentVariable = "SAV_ATTESTATION_STORE_ROOT";

    /// <summary>
    /// Optional JSON object mapping alias → DSN environment variable <em>name</em>
    /// (never DSN values), e.g. <c>{"prod_ro":"SAV_TARGET_PROD_RO_DSN"}</c>.
    /// </summary>
    public const string TargetsJsonEnvironmentVariable = "SAV_TARGETS_JSON";

    /// <summary>Optional file under ConfigRoot with the same JSON shape as <see cref="TargetsJsonEnvironmentVariable"/>.</summary>
    public const string TargetsFileName = "targets.json";

    private static readonly Regex EnvVarNamePattern = new(
        "^[A-Za-z_][A-Za-z0-9_]*$",
        RegexOptions.CultureInvariant | RegexOptions.Compiled);

    public DiProfile Mode { get; init; } = DiProfile.Full;

    /// <summary>Absolute config root; empty means process CWD at resolver construction.</summary>
    public string ConfigRoot { get; init; } = string.Empty;

    /// <summary>Absolute attestation store root (Full mode).</summary>
    public string AttestationStoreRoot { get; init; } = string.Empty;

    /// <summary>Alias → DSN environment variable name (never DSN values).</summary>
    public Dictionary<string, string> AliasToDsnEnvVar { get; init; } =
        new(StringComparer.OrdinalIgnoreCase);

    public ConfigRootOptions ToConfigRootOptions() =>
        new() { ConfigRoot = ConfigRoot };

    public static DiProfile ResolveMode(string? modeValue)
    {
        if (string.IsNullOrWhiteSpace(modeValue))
        {
            return DiProfile.Full;
        }

        if (modeValue.Equals(nameof(DiProfile.AnalyzeOnly), StringComparison.OrdinalIgnoreCase))
        {
            return DiProfile.AnalyzeOnly;
        }

        if (modeValue.Equals(nameof(DiProfile.Full), StringComparison.OrdinalIgnoreCase))
        {
            return DiProfile.Full;
        }

        throw new SavException(
            SavErrorCode.ModeInvalid,
            $"{SavErrorCode.ModeInvalid}: Unknown Sav mode '{modeValue}'. Expected AnalyzeOnly or Full.");
    }

    public static DiProfile ResolveModeFromEnvironment() =>
        ResolveMode(Environment.GetEnvironmentVariable(ModeEnvironmentVariable));

    public static SavModeOptions FromEnvironment(DiProfile? modeOverride = null)
    {
        DiProfile mode = modeOverride ?? ResolveModeFromEnvironment();
        string configRoot = Environment.GetEnvironmentVariable(ConfigRootEnvironmentVariable) ?? string.Empty;
        string storeRoot = Environment.GetEnvironmentVariable(AttestationStoreRootEnvironmentVariable)
            ?? DefaultAttestationStoreRoot();

        return new SavModeOptions
        {
            Mode = mode,
            ConfigRoot = configRoot,
            AttestationStoreRoot = storeRoot,
            AliasToDsnEnvVar = LoadTargetsFromEnvironment(configRoot),
        };
    }

    public static string DefaultAttestationStoreRoot()
    {
        string baseDir = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if (string.IsNullOrWhiteSpace(baseDir))
        {
            baseDir = Path.GetTempPath();
        }

        return Path.GetFullPath(Path.Combine(baseDir, "sav", "attestations"));
    }

    /// <summary>
    /// Loads alias → DSN env-var <em>name</em> map from <c>targets.json</c> under ConfigRoot
    /// and/or <see cref="TargetsJsonEnvironmentVariable"/> (env overlays file). Names only, not DSN values.
    /// </summary>
    private static Dictionary<string, string> LoadTargetsFromEnvironment(string configRoot)
    {
        Dictionary<string, string> map = new(StringComparer.OrdinalIgnoreCase);

        string? fileJson = TryReadTargetsFile(configRoot);
        if (fileJson is not null)
        {
            MergeTargetsJson(map, fileJson, TargetsFileName);
        }

        string? envJson = Environment.GetEnvironmentVariable(TargetsJsonEnvironmentVariable);
        if (!string.IsNullOrWhiteSpace(envJson))
        {
            MergeTargetsJson(map, envJson, TargetsJsonEnvironmentVariable);
        }

        return map;
    }

    private static string? TryReadTargetsFile(string configRoot)
    {
        string root = string.IsNullOrWhiteSpace(configRoot)
            ? Directory.GetCurrentDirectory()
            : configRoot;
        string fullRoot = Path.GetFullPath(root);
        string path = Path.Combine(fullRoot, TargetsFileName);
        if (!File.Exists(path))
        {
            // An absent optional targets.json must not prevent environment-based aliases.
            return null;
        }

        // Reuse the same lexical, symlink, reparse-point, and final-path checks
        // applied to policy/contract files. A lexical containment check alone
        // allows targets.json to redirect alias names to an external file.
        string validatedPath = new ConfigPathResolver(new ConfigRootOptions { ConfigRoot = fullRoot })
            .ResolveUnderConfigRoot(TargetsFileName);
        return File.ReadAllText(validatedPath);
    }

    private static void MergeTargetsJson(
        Dictionary<string, string> map,
        string json,
        string source)
    {
        Dictionary<string, string>? parsed;
        try
        {
            parsed = JsonSerializer.Deserialize<Dictionary<string, string>>(json);
        }
        catch (JsonException)
        {
            throw new SavException(
                SavErrorCode.PolicyInvalid,
                $"{SavErrorCode.PolicyInvalid}: Invalid targets mapping JSON ({source}).");
        }

        if (parsed is null)
        {
            return;
        }

        foreach (KeyValuePair<string, string> pair in parsed)
        {
            string alias = pair.Key?.Trim() ?? string.Empty;
            string envVarName = pair.Value?.Trim() ?? string.Empty;
            if (string.IsNullOrWhiteSpace(alias) || string.IsNullOrWhiteSpace(envVarName))
            {
                throw new SavException(
                    SavErrorCode.PolicyInvalid,
                    $"{SavErrorCode.PolicyInvalid}: Targets mapping entries require non-empty alias and env-var name ({source}).");
            }

            if (LooksLikeConnectionString(envVarName) || !EnvVarNamePattern.IsMatch(envVarName))
            {
                throw new SavException(
                    SavErrorCode.AliasLooksLikeDsn,
                    $"{SavErrorCode.AliasLooksLikeDsn}: Targets mapping values must be DSN environment variable names, not connection strings.");
            }

            map[alias] = envVarName;
        }
    }

    private static bool LooksLikeConnectionString(string value) =>
        value.Contains("://", StringComparison.Ordinal)
        || value.Contains('=', StringComparison.Ordinal)
        || value.Contains("Host=", StringComparison.OrdinalIgnoreCase)
        || value.Contains("Password=", StringComparison.OrdinalIgnoreCase)
        || value.Contains("Username=", StringComparison.OrdinalIgnoreCase)
        || value.Contains("Server=", StringComparison.OrdinalIgnoreCase);
}
