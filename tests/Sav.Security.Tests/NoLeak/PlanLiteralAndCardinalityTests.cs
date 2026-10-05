using System.Text.Json;
using Sav.Domain.Policies;
using Sav.Infrastructure.Postgres.Plans;
using Sav.Infrastructure.Postgres.Redaction;

namespace Sav.Security.Tests.NoLeak;

public sealed class PlanLiteralAndCardinalityTests
{
    [Fact]
    public void Bucketed_summary_strips_filter_and_exact_rows()
    {
        const string canary = "CANARY_LITERAL_do_not_egress@example.invalid";
        string explainJson =
            """
            [{
              "Plan": {
                "Node Type": "Seq Scan",
                "Relation Name": "secrets",
                "Alias": "secrets",
                "Startup Cost": 0.00,
                "Total Cost": 25.00,
                "Plan Rows": 123456,
                "Plan Width": 32,
                "Filter": "(note = 'CANARY_LITERAL_do_not_egress@example.invalid')",
                "Output": ["id", "note"]
              }
            }]
            """;

        DisclosureProfile strict = new("strict", false, false, false, false);
        var summary = ExplainPlanProvider.ParseAndBucket(explainJson, strict);
        string json = JsonSerializer.Serialize(summary);

        Assert.Equal("low", summary.CostBucket);
        Assert.DoesNotContain(canary, json, StringComparison.Ordinal);
        Assert.DoesNotContain("123456", json, StringComparison.Ordinal);
        Assert.DoesNotContain("Filter", json, StringComparison.Ordinal);
        Assert.DoesNotContain("Output", json, StringComparison.Ordinal);
        Assert.DoesNotContain("Plan Rows", json, StringComparison.Ordinal);
        Assert.Contains("Seq Scan", summary.NodeTypes);
    }

    [Fact]
    public void Redactor_removes_plan_literals_from_errors()
    {
        MinimalStrictRedactor redactor = new();
        DisclosureProfile strict = new("strict", false, false, false, false);
        string redacted = redactor.RedactText(
            "DETAIL: Filter (note = 'CANARY_LITERAL_do_not_egress@example.invalid')",
            strict);
        Assert.DoesNotContain("CANARY_LITERAL", redacted, StringComparison.OrdinalIgnoreCase);
    }
}
