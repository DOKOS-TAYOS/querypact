using Sav.Domain.Targets;

namespace Sav.Application.Abstractions;

/// <summary>
/// Resolves an operator alias to <see cref="TargetAlias"/> (fingerprint from alias + env-var name; never DSN value).
/// DSN only from environment / protected local config: never agent-supplied arguments. Does not open PostgreSQL.
/// </summary>
public interface ITargetAliasResolver
{
    TargetAlias Resolve(string aliasName);
}
