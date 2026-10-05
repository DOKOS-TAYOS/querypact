using Sav.Application.Abstractions;
using Sav.Infrastructure.Postgres.Redaction;

namespace Sav.Host.Redaction;

/// <summary>
/// Shared Host egress redactor for CLI/MCP error paths (parity with DI <see cref="IRedactor"/> stack).
/// </summary>
internal static class HostErrorRedactor
{
    public static IRedactor Create() => new PostgresErrorRedactor(new StrictRedactor());
}
