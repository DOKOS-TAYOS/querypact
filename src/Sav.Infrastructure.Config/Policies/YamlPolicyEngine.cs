using Sav.Application.Abstractions;
using Sav.Domain.Analysis;
using Sav.Domain.Decisions;
using Sav.Domain.Policies;

namespace Sav.Infrastructure.Config.Policies;

public sealed class YamlPolicyEngine : IPolicyEngine
{
    public Task<PolicyDecision> EvaluateAsync(
        SqlAnalysis analysis,
        Policy policy,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(analysis);
        ArgumentNullException.ThrowIfNull(policy);

        List<string> ruleIds = [];

        if (!analysis.IsParsable || analysis.Ir.StatementTypes.Count == 0)
        {
            return Task.FromResult(Deny(["sql_unparsable"], ["sql_unparsable"]));
        }

        SqlIr ir = analysis.Ir;

        if (policy.DenyMultipleStatements && ir.HasMultipleStatements)
        {
            ruleIds.Add("multiple_statements");
        }

        foreach (string statementType in ir.StatementTypes)
        {
            if (!policy.AllowedStatementTypes.Contains(statementType, StringComparer.OrdinalIgnoreCase))
            {
                ruleIds.Add("forbidden_statement_type");
                break;
            }
        }

        if (ContainsDeniedName(ir.TablesRead, policy.DeniedTables) ||
            ContainsDeniedName(ir.TablesWritten, policy.DeniedTables))
        {
            ruleIds.Add("denied_table");
        }

        if (ContainsDeniedName(ir.ColumnsRead, policy.DeniedColumns) ||
            ContainsDeniedName(ir.ColumnsWritten, policy.DeniedColumns))
        {
            ruleIds.Add("denied_column");
        }

        if (ir.Functions.Count > 0)
        {
            foreach (string function in ir.Functions)
            {
                if (policy.AllowedFunctions.Count == 0 ||
                    !policy.AllowedFunctions.Contains(function, StringComparer.Ordinal))
                {
                    ruleIds.Add("unknown_function");
                    break;
                }
            }
        }

        if (policy.DenyUnresolvedObjects && ir.UnresolvedObjects.Count > 0)
        {
            ruleIds.Add("unresolved_object");
        }

        if (policy.DenyUpdateDeleteWithoutPredicate &&
            ir.RiskCodes.Contains("missing_predicate", StringComparer.OrdinalIgnoreCase) &&
            ir.StatementTypes.Any(t => t is "Update" or "Delete"))
        {
            ruleIds.Add("missing_predicate");
        }

        if (ir.RiskCodes.Contains("unsupported_construct", StringComparer.OrdinalIgnoreCase) ||
            ir.HasDynamicSql)
        {
            ruleIds.Add("unsupported_construct");
        }

        if (ruleIds.Count > 0)
        {
            IReadOnlyList<string> distinct = ruleIds.Distinct(StringComparer.Ordinal).OrderBy(x => x, StringComparer.Ordinal).ToArray();
            return Task.FromResult(Deny(distinct, distinct));
        }

        if (ir.RiskCodes.Contains("needs_review", StringComparer.OrdinalIgnoreCase))
        {
            return Task.FromResult(new PolicyDecision(
                PolicyOutcome.Review,
                reasons: ["needs_review"],
                ruleIds: ["needs_review"]));
        }

        return Task.FromResult(new PolicyDecision(
            PolicyOutcome.Allow,
            reasons: [],
            ruleIds: []));
    }

    private static bool ContainsDeniedName(IReadOnlyList<string> names, IReadOnlyList<string> denied) =>
        names.Any(name => denied.Any(deniedName => NamesMatch(name, deniedName)));

    private static bool NamesMatch(string name, string deniedName)
    {
        if (string.Equals(name, deniedName, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        bool nameQualified = name.Contains('.');
        bool deniedQualified = deniedName.Contains('.');
        if (nameQualified && deniedQualified)
        {
            return false;
        }

        return string.Equals(
            UnqualifiedName(name),
            UnqualifiedName(deniedName),
            StringComparison.OrdinalIgnoreCase);
    }

    private static string UnqualifiedName(string name)
    {
        int separator = name.LastIndexOf('.');
        return separator >= 0 ? name[(separator + 1)..] : name;
    }

    private static PolicyDecision Deny(IReadOnlyList<string> reasons, IReadOnlyList<string> ruleIds) =>
        new(PolicyOutcome.Deny, reasons, ruleIds);
}
