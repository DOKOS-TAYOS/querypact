using System.Security.Cryptography;
using System.Text;
using Sav.Application.Abstractions;
using Sav.Domain.Errors;
using Sav.Domain.Targets;

namespace Sav.Infrastructure.Postgres.Targets;

public sealed class TargetAliasResolver : ITargetAliasResolver
{
    private readonly TargetsBindingOptions _options;

    public TargetAliasResolver(TargetsBindingOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        _options = options;
    }

    public TargetAlias Resolve(string aliasName)
    {
        if (string.IsNullOrWhiteSpace(aliasName))
        {
            throw new SavException(SavErrorCode.AliasUnknown, "alias_unknown: Alias is required.");
        }

        if (LooksLikeConnectionString(aliasName))
        {
            throw new SavException(
                SavErrorCode.AliasLooksLikeDsn,
                "alias_looks_like_dsn: Target must be an operator alias, not a connection string.");
        }

        if (!_options.AliasToDsnEnvVar.TryGetValue(aliasName, out string? envVarName)
            || string.IsNullOrWhiteSpace(envVarName))
        {
            throw new SavException(SavErrorCode.AliasUnknown, "alias_unknown: Alias is not configured.");
        }

        string? dsn = Environment.GetEnvironmentVariable(envVarName);
        if (string.IsNullOrWhiteSpace(dsn))
        {
            throw new SavException(
                SavErrorCode.AliasDsnMissing,
                "alias_dsn_missing: DSN environment variable is not set for the alias.");
        }

        string fingerprint = ComputeFingerprint(aliasName, envVarName);
        return new TargetAlias(aliasName, fingerprint);
    }

    internal static string ComputeFingerprint(string aliasName, string envVarName)
    {
        // Aliases resolve case-insensitively; their attestation identity must do the same.
        byte[] bytes = Encoding.UTF8.GetBytes(aliasName.ToLowerInvariant() + "\0" + envVarName);
        byte[] hash = SHA256.HashData(bytes);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private static bool LooksLikeConnectionString(string value)
    {
        if (value.Contains("://", StringComparison.Ordinal)
            || value.Contains("Host=", StringComparison.OrdinalIgnoreCase)
            || value.Contains("Username=", StringComparison.OrdinalIgnoreCase)
            || value.Contains("Password=", StringComparison.OrdinalIgnoreCase)
            || value.Contains("Server=", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return false;
    }
}
