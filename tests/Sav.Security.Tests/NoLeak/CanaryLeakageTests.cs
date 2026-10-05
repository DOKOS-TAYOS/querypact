using Sav.Application.Abstractions;
using Sav.Domain.Policies;
using Sav.Infrastructure.Postgres.Redaction;

namespace Sav.Security.Tests.NoLeak;

public sealed class CanaryLeakageTests
{
    private const string Canary = "CANARY_LITERAL_do_not_egress@example.invalid";

    private static readonly DisclosureProfile Strict = DisclosureProfileMerge.StrictDefaults();

    public static TheoryData<string> CanaryInputs { get; } = new()
    {
        "SELECT '" + Canary + "' AS x",
        "password=super-secret-password",
        "Host=evil.example;Password=leak",
        "postgresql://user:pass@host:5432/db",
        "DETAIL: row=(" + Canary + ")",
        "NOTICE: " + Canary,
        "HINT: try password=abc",
        "CONTEXT: PL/pgSQL function leak()",
        "boom\n   at Sav.Infrastructure.Postgres.Targets.ReadOnlySession.Open()",
    };

    [Theory]
    [MemberData(nameof(CanaryInputs))]
    public void Strict_stack_strips_canaries_and_secrets(string input)
    {
        IRedactor redactor = CreateStack();
        string redacted = redactor.RedactText(input, Strict);

        Assert.DoesNotContain(Canary, redacted, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("super-secret-password", redacted, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("postgresql://", redacted, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Password=leak", redacted, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("at Sav.Infrastructure", redacted, StringComparison.Ordinal);
        Assert.Contains(StrictRedactor.RedactedToken, redacted, StringComparison.Ordinal);
    }

    [Fact]
    public void RedactObject_string_does_not_mutate_input()
    {
        const string original = "password=keep-original-intact";
        IRedactor redactor = CreateStack();
        string redacted = redactor.RedactObject(original, Strict);
        Assert.Equal("password=keep-original-intact", original);
        Assert.DoesNotContain("keep-original-intact", redacted, StringComparison.Ordinal);
    }

    private static IRedactor CreateStack() => new PostgresErrorRedactor(new StrictRedactor());
}
