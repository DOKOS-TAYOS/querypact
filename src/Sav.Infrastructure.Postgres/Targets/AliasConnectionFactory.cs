using Npgsql;
using Sav.Domain.Errors;
using Sav.Domain.Targets;

namespace Sav.Infrastructure.Postgres.Targets;

/// <summary>
/// Builds unopened <see cref="NpgsqlConnection"/> instances from alias → env-var DSN bindings.
/// Does not open or connect; callers own when the connection goes live.
/// </summary>
public sealed class AliasConnectionFactory
{
    private readonly TargetsBindingOptions _options;

    public AliasConnectionFactory(TargetsBindingOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        _options = options;
    }

    public NpgsqlConnection Create(TargetAlias target)
    {
        ArgumentNullException.ThrowIfNull(target);

        if (!_options.AliasToDsnEnvVar.TryGetValue(target.Alias, out string? envVarName)
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

        return new NpgsqlConnection(dsn);
    }

    internal string RequireDsn(TargetAlias target)
    {
        ArgumentNullException.ThrowIfNull(target);

        if (!_options.AliasToDsnEnvVar.TryGetValue(target.Alias, out string? envVarName)
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

        return dsn;
    }
}
