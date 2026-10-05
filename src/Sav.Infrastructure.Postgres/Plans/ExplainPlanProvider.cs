using System.Text.Json;
using Sav.Application.Abstractions;
using Sav.Domain.Decisions;
using Sav.Domain.Errors;
using Sav.Domain.Plans;
using Sav.Domain.Policies;
using Sav.Domain.Targets;

namespace Sav.Infrastructure.Postgres.Plans;

public sealed class ExplainPlanProvider : IPlanProvider
{
    private static readonly HashSet<string> RiskNodeTypes = new(StringComparer.Ordinal)
    {
        "Seq Scan",
        "Nested Loop",
        "Gather",
        "Gather Merge",
    };

    private readonly IRedactor _redactor;

    public ExplainPlanProvider(IRedactor redactor)
    {
        ArgumentNullException.ThrowIfNull(redactor);
        _redactor = redactor;
    }

    public async Task<PlanGateResult> GetEstimatedPlanAsync(
        TargetAlias target,
        string sql,
        PolicyDecision decision,
        Policy policy,
        IReadOnlySession? session,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(target);
        ArgumentNullException.ThrowIfNull(decision);
        ArgumentNullException.ThrowIfNull(policy);
        cancellationToken.ThrowIfCancellationRequested();

        if (decision.Outcome is PolicyOutcome.Deny or PolicyOutcome.Review)
        {
            PlanGateOutcome mapped = decision.Outcome == PolicyOutcome.Deny
                ? PlanGateOutcome.Deny
                : PlanGateOutcome.Review;
            return new PlanGateResult(mapped, decision.Reasons.ToArray(), summary: null);
        }

        if (session is null)
        {
            throw new SavException(SavErrorCode.SessionRequired, "session_required: plan gate Allow requires session.");
        }

        if (string.IsNullOrWhiteSpace(sql))
        {
            throw new SavException(SavErrorCode.UnsupportedConstruct, "unsupported_construct: SQL is required.");
        }

        try
        {
            // Estimated plan only: never run ANALYZE options by default.
            string explainSql = "EXPLAIN (FORMAT JSON) " + sql;
            IReadOnlyList<OracleScalarRow> rows = await session.ExecuteReaderAsync(
                    explainSql,
                    [new OracleScalarColumn("QUERY PLAN", OracleScalarKind.StringV)],
                    cancellationToken)
                .ConfigureAwait(false);

            string? json = rows.FirstOrDefault()?.StringV;
            if (string.IsNullOrWhiteSpace(json))
            {
                throw new SavException(SavErrorCode.QueryFailed, "query_failed: empty plan.");
            }

            PlanSummary summary = ParseAndBucket(json, policy.Disclosure);
            return PlanNodePolicy.Evaluate(summary, policy);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (SavException)
        {
            throw;
        }
        catch (Exception ex)
        {
            string message = _redactor.RedactText(ex.Message, policy.Disclosure);
            throw new SavException(SavErrorCode.QueryFailed, "query_failed: " + message);
        }
    }

    internal static PlanSummary ParseAndBucket(string explainJson, DisclosureProfile disclosure)
    {
        using JsonDocument document = JsonDocument.Parse(explainJson);
        JsonElement root = document.RootElement;
        JsonElement planElement = root;
        if (root.ValueKind == JsonValueKind.Array && root.GetArrayLength() > 0)
        {
            planElement = root[0].GetProperty("Plan");
        }
        else if (root.TryGetProperty("Plan", out JsonElement direct))
        {
            planElement = direct;
        }

        double totalCost = ReadTotalCost(planElement);
        List<string> nodeTypes = [];
        List<string> riskFlags = [];
        CollectNodes(planElement, nodeTypes, riskFlags);

        IReadOnlyList<string> filteredNodes = nodeTypes
            .Distinct(StringComparer.Ordinal)
            .OrderBy(n => n, StringComparer.Ordinal)
            .ToArray();

        IReadOnlyList<string> filteredRisks = riskFlags
            .Distinct(StringComparer.Ordinal)
            .OrderBy(n => n, StringComparer.Ordinal)
            .ToArray();

        // Strict disclosure: never emit raw plan / exact cardinalities; summary is already bucketed.
        _ = disclosure;
        return new PlanSummary(PlanBucketer.Bucketize(totalCost), filteredNodes, filteredRisks);
    }

    private static double ReadTotalCost(JsonElement plan)
    {
        if (plan.TryGetProperty("Total Cost", out JsonElement cost)
            && cost.TryGetDouble(out double value))
        {
            return value;
        }

        return 0d;
    }

    private static void CollectNodes(JsonElement plan, List<string> nodeTypes, List<string> riskFlags)
    {
        if (plan.TryGetProperty("Node Type", out JsonElement nodeTypeElement))
        {
            string? nodeType = nodeTypeElement.GetString();
            if (!string.IsNullOrWhiteSpace(nodeType))
            {
                nodeTypes.Add(nodeType);
                if (RiskNodeTypes.Contains(nodeType))
                {
                    riskFlags.Add("node:" + nodeType);
                }
            }
        }

        if (plan.TryGetProperty("Plans", out JsonElement plans)
            && plans.ValueKind == JsonValueKind.Array)
        {
            foreach (JsonElement child in plans.EnumerateArray())
            {
                CollectNodes(child, nodeTypes, riskFlags);
            }
        }
    }
}
