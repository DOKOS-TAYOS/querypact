using Sav.Domain.Attestations;
using Sav.Domain.Decisions;
using Sav.Domain.Policies;
using Sav.Domain.Properties;
using Sav.Infrastructure.Postgres.Redaction;

namespace Sav.Security.Tests.NoLeak;

public sealed class MinimalRedactorCanaryTests
{
    private static readonly DisclosureProfile Strict = new(
        "strict",
        IncludePlanSummary: false,
        IncludeObjectNames: false,
        IncludeTimings: false,
        IncludeRowCounts: false);

    [Theory]
    [InlineData("CANARY_LITERAL_do_not_egress@example.invalid")]
    [InlineData("password=super-secret-password")]
    [InlineData("Host=evil.example;Password=leak")]
    [InlineData("postgresql://user:pass@host:5432/db")]
    [InlineData("DETAIL: secret row value xyz")]
    [InlineData("HINT: try password=abc")]
    [InlineData("CONTEXT: PL/pgSQL function leak()")]
    [InlineData("NOTICE: canary payload")]
    public void RedactText_removes_sensitive_patterns(string input)
    {
        MinimalStrictRedactor redactor = new();
        string redacted = redactor.RedactText(input, Strict);

        Assert.DoesNotContain("CANARY_LITERAL", redacted, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("super-secret-password", redacted, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("postgresql://", redacted, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Password=leak", redacted, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("secret row value", redacted, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(MinimalStrictRedactor.RedactedToken, redacted, StringComparison.Ordinal);
    }

    [Fact]
    public void RedactText_strips_stack_frames()
    {
        MinimalStrictRedactor redactor = new();
        string input = "boom\n   at Sav.Infrastructure.Postgres.Targets.ReadOnlySession.Open()\n   at System.Runtime.CompilerServices.TaskAwaiter.HandleNonSuccess()";
        string redacted = redactor.RedactText(input, Strict);
        Assert.DoesNotContain("at Sav.Infrastructure", redacted, StringComparison.Ordinal);
        Assert.DoesNotContain("TaskAwaiter", redacted, StringComparison.Ordinal);
    }

    [Fact]
    public void RedactObject_string_clone_does_not_mutate_input()
    {
        MinimalStrictRedactor redactor = new();
        const string original = "password=keep-original-intact";
        string redacted = redactor.RedactObject(original, Strict);
        Assert.Equal("password=keep-original-intact", original);
        Assert.DoesNotContain("keep-original-intact", redacted, StringComparison.Ordinal);
    }

    [Fact]
    public void RedactObject_attestation_fails_closed()
    {
        MinimalStrictRedactor redactor = new();
        StructuralSqlIr ir = new(
            "postgresql",
            ["SelectStmt"],
            [],
            [],
            [],
            [],
            [],
            false,
            false,
            [],
            []);
        Attestation attestation = new(
            "1",
            "id",
            "sql",
            "contract",
            "policy",
            "0.0.0",
            "fp",
            AttestationDecision.Pass,
            new AttestationAnalysis(ir, true),
            null,
            [],
            Strict,
            DateTimeOffset.UtcNow,
            "hmac");

        InvalidOperationException ex = Assert.Throws<InvalidOperationException>(
            () => redactor.RedactObject(attestation, Strict));
        Assert.Contains("StrictRedactor", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void RedactObject_property_result_fails_closed()
    {
        MinimalStrictRedactor redactor = new();
        PropertyResult property = new("query_succeeds", PropertyStatus.Fail, "query_failed");
        InvalidOperationException ex = Assert.Throws<InvalidOperationException>(
            () => redactor.RedactObject(property, Strict));
        Assert.Contains("StrictRedactor", ex.Message, StringComparison.Ordinal);
    }
}
