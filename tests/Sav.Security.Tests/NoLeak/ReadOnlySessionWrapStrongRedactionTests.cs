using Sav.Application.Abstractions;
using Sav.Domain.Policies;
using Sav.Infrastructure.Postgres.Redaction;

namespace Sav.Security.Tests.NoLeak;

/// <summary>
/// M2: RO session Wrap must use the strong redaction stack (PostgresErrorRedactor + StrictRedactor),
/// not MinimalStrictRedactor alone: Key (...)=(...) and SQLSTATE canaries must not egress.
/// </summary>
public sealed class ReadOnlySessionWrapStrongRedactionTests
{
    private const string Canary = "CANARY_KEY_do_not_egress@example.invalid";

    private static readonly DisclosureProfile Strict = new(
        "strict",
        IncludePlanSummary: false,
        IncludeObjectNames: false,
        IncludeTimings: false,
        IncludeRowCounts: false);

    [Fact]
    public void Ro_wrap_redactor_scrubs_key_tuple_and_sqlstate_canary()
    {
        // Same message shape as Postgres unique_violation / RO Wrap path (no DETAIL: prefix).
        string raw = $"Key (email)=({Canary}) already exists. SQLSTATE 23505";

        // Production RO Wrap stack under test (must match DI / fixture wiring for session Wrap).
        IRedactor redactor = CreateRoWrapRedactor();
        string message = "query_failed: " + redactor.RedactText(raw, Strict);

        Assert.DoesNotContain(Canary, message, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("23505", message, StringComparison.Ordinal);
        Assert.DoesNotContain("email", message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("[REDACTED]", message, StringComparison.Ordinal);
    }

    /// <summary>
    /// Mirrors the redactor stack wired into ReadOnlySession / Guard / Factory / ExplainPlanProvider.
    /// </summary>
    private static IRedactor CreateRoWrapRedactor() =>
        new PostgresErrorRedactor(new StrictRedactor());
}
