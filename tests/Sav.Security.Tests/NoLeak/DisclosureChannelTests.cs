using Sav.Application.Abstractions;
using Sav.Domain.Decisions;
using Sav.Domain.Errors;
using Sav.Domain.Plans;
using Sav.Domain.Policies;
using Sav.Domain.Properties;
using Sav.Infrastructure.Postgres.Redaction;

namespace Sav.Security.Tests.NoLeak;

public sealed class DisclosureChannelTests
{
    private static IRedactor CreateStack() => new PostgresErrorRedactor(new StrictRedactor());

    [Fact]
    public void IncludeRowCounts_false_strips_exact_counts()
    {
        DisclosureProfile profile = new("strict", false, false, false, IncludeRowCounts: false);
        string redacted = CreateStack().RedactText("query returned rows=123456", profile);
        Assert.DoesNotContain("123456", redacted, StringComparison.Ordinal);
        Assert.Contains(StrictRedactor.RedactedToken, redacted, StringComparison.Ordinal);
    }

    [Fact]
    public void IncludeRowCounts_true_buckets_exact_counts()
    {
        DisclosureProfile profile = new("counts", false, false, false, IncludeRowCounts: true);
        string redacted = CreateStack().RedactText("query returned rows=123456", profile);
        Assert.DoesNotContain("123456", redacted, StringComparison.Ordinal);
        Assert.Contains(StrictRedactor.BucketCount(123456), redacted, StringComparison.Ordinal);
    }

    [Fact]
    public void IncludeTimings_false_strips_exact_ms()
    {
        DisclosureProfile profile = new("strict", false, false, IncludeTimings: false, false);
        string redacted = CreateStack().RedactText("elapsed 1234.5 ms", profile);
        Assert.DoesNotContain("1234.5", redacted, StringComparison.Ordinal);
        Assert.Contains(StrictRedactor.RedactedToken, redacted, StringComparison.Ordinal);
    }

    [Fact]
    public void IncludeTimings_true_buckets_exact_ms()
    {
        DisclosureProfile profile = new("timings", false, false, IncludeTimings: true, false);
        string redacted = CreateStack().RedactText("elapsed 1234.5 ms", profile);
        Assert.DoesNotContain("1234.5", redacted, StringComparison.Ordinal);
        Assert.Contains(StrictRedactor.BucketTimingMs(1234.5), redacted, StringComparison.Ordinal);
    }

    [Fact]
    public void IncludeObjectNames_false_redacts_relation_names()
    {
        DisclosureProfile profile = new("strict", false, IncludeObjectNames: false, false, false);
        string redacted = CreateStack().RedactText("Relation Name: secrets_table", profile);
        Assert.DoesNotContain("secrets_table", redacted, StringComparison.Ordinal);
        Assert.Contains(StrictRedactor.RedactedToken, redacted, StringComparison.Ordinal);
    }

    [Fact]
    public void IncludePlanSummary_false_strips_explain_filter_literals()
    {
        const string canary = "CANARY_LITERAL_do_not_egress@example.invalid";
        DisclosureProfile profile = new("strict", IncludePlanSummary: false, false, false, false);
        string redacted = CreateStack().RedactText(
            "Filter: (note = '" + canary + "') Output: [id]",
            profile);
        Assert.DoesNotContain(canary, redacted, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Output:", redacted, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void PropertyResult_unknown_free_text_coerces_to_query_failed_when_counts_disallowed()
    {
        DisclosureProfile profile = DisclosureProfileMerge.StrictDefaults();
        PropertyResult draft = new(
            "shadow_apply",
            PropertyStatus.Fail,
            "relation \"secret_orders\" does not exist");
        PropertyResult redacted = CreateStack().RedactObject(draft, profile);
        Assert.Equal(SavErrorCode.QueryFailed, redacted.RedactedDetail);
        Assert.DoesNotContain("secret_orders", redacted.RedactedDetail!, StringComparison.Ordinal);
        Assert.DoesNotContain("relation", redacted.RedactedDetail!, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(SavErrorCode.SchemaChanged)]
    [InlineData(SavErrorCode.SchemaInvariantFailed)]
    [InlineData(SavErrorCode.OrphansFound)]
    [InlineData(SavErrorCode.NotEquivalent)]
    [InlineData(SavErrorCode.AffectedRowsOutOfRange)]
    [InlineData(SavErrorCode.PropertyEnvironmentForbidden)]
    public void PropertyResult_production_fixed_codes_preserved(string code)
    {
        DisclosureProfile profile = DisclosureProfileMerge.StrictDefaults();
        PropertyResult draft = new("prop", PropertyStatus.Fail, code);
        PropertyResult redacted = CreateStack().RedactObject(draft, profile);
        Assert.Equal(code, redacted.RedactedDetail);
    }

    [Fact]
    public void PropertyResult_with_exact_v_stripped_when_counts_disallowed()
    {
        DisclosureProfile profile = DisclosureProfileMerge.StrictDefaults();
        PropertyResult draft = new("unique", PropertyStatus.Fail, "v=42");
        PropertyResult redacted = CreateStack().RedactObject(draft, profile);
        Assert.Equal(SavErrorCode.UniqueViolation, redacted.RedactedDetail);
        Assert.DoesNotContain("42", redacted.RedactedDetail!, StringComparison.Ordinal);
        Assert.Equal("v=42", draft.RedactedDetail);
    }

    [Fact]
    public void PlanSummary_omits_nodes_when_plan_channel_closed()
    {
        DisclosureProfile profile = new("strict", IncludePlanSummary: false, true, false, false);
        PlanSummary summary = new("low", ["Seq Scan"], ["ok"]);
        PlanSummary redacted = CreateStack().RedactObject(summary, profile);
        Assert.Empty(redacted.NodeTypes);
        Assert.Equal("low", redacted.CostBucket);
        Assert.Single(summary.NodeTypes);
    }
}
