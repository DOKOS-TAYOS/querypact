using System.Text.RegularExpressions;
using Sav.Application.Abstractions;
using Sav.Domain.Policies;

namespace Sav.Infrastructure.Postgres.Redaction;

/// <summary>
/// Redacts PostgreSQL error / NOTICE / RAISE channels, then delegates remaining disclosure
/// rules to an inner <see cref="IRedactor"/>.
/// </summary>
public sealed partial class PostgresErrorRedactor : IRedactor
{
    private readonly IRedactor _inner;

    public PostgresErrorRedactor(IRedactor inner)
    {
        ArgumentNullException.ThrowIfNull(inner);
        _inner = inner;
    }

    public string RedactText(string value, DisclosureProfile profile)
    {
        ArgumentNullException.ThrowIfNull(profile);
        if (string.IsNullOrEmpty(value))
        {
            return value;
        }

        string scrubbed = PgChannelPattern().Replace(value, "$1" + StrictRedactor.RedactedToken);
        scrubbed = SqlstatePattern().Replace(scrubbed, "SQLSTATE " + StrictRedactor.RedactedToken);
        scrubbed = KeyTuplePattern().Replace(scrubbed, "Key " + StrictRedactor.RedactedToken);
        return _inner.RedactText(scrubbed, profile);
    }

    public T RedactObject<T>(T value, DisclosureProfile profile)
    {
        ArgumentNullException.ThrowIfNull(profile);
        if (value is string text)
        {
            return (T)(object)RedactText(text, profile);
        }

        if (value is Exception ex)
        {
            string redactedMessage = RedactText(ex.Message, profile);
            if (ex is Domain.Errors.SavException sav)
            {
                return (T)(object)new Domain.Errors.SavException(sav.Code, redactedMessage);
            }

            return (T)(object)new Exception(redactedMessage);
        }

        return _inner.RedactObject(value, profile);
    }

    [GeneratedRegex(@"\b(DETAIL|HINT|CONTEXT|NOTICE|RAISE)\s*:\s*.+$", RegexOptions.IgnoreCase | RegexOptions.Multiline | RegexOptions.CultureInvariant)]
    private static partial Regex PgChannelPattern();

    [GeneratedRegex(@"\bSQLSTATE\s+[A-Z0-9]+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex SqlstatePattern();

    [GeneratedRegex(@"\bKey\s+\([^)]+\)=\([^)]+\)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex KeyTuplePattern();
}
