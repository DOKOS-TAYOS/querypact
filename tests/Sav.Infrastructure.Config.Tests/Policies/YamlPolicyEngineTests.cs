using Sav.Application.Abstractions;
using Sav.Domain.Analysis;
using Sav.Domain.Decisions;
using Sav.Domain.Policies;
using Sav.Infrastructure.Config.Policies;

namespace Sav.Infrastructure.Config.Tests.Policies;

public sealed class YamlPolicyEngineTests
{
    private readonly IPolicyEngine _engine = new YamlPolicyEngine();

    [Fact]
    public async Task Denies_parsable_analysis_without_statements()
    {
        Policy policy = CreatePolicy(denyUnresolvedObjects: false);
        SqlAnalysis analysis = Analysis(statementTypes: [], isParsable: true);

        PolicyDecision decision = await _engine.EvaluateAsync(analysis, policy, CancellationToken.None);

        Assert.Equal(PolicyOutcome.Deny, decision.Outcome);
        Assert.Contains("sql_unparsable", decision.RuleIds);
    }

    [Fact]
    public async Task Allows_select_when_policy_permits()
    {
        Policy policy = CreatePolicy(denyUnresolvedObjects: false);
        SqlAnalysis analysis = Analysis(
            statementTypes: ["Select"],
            tablesRead: ["users"],
            columnsRead: ["id"],
            isParsable: true);

        PolicyDecision decision = await _engine.EvaluateAsync(analysis, policy, CancellationToken.None);

        Assert.Equal(PolicyOutcome.Allow, decision.Outcome);
        Assert.Empty(decision.Reasons);
    }

    [Fact]
    public async Task Denies_unparsable_analysis()
    {
        Policy policy = CreatePolicy(denyUnresolvedObjects: false);
        SqlAnalysis analysis = Analysis(
            statementTypes: [],
            isParsable: false);

        PolicyDecision decision = await _engine.EvaluateAsync(analysis, policy, CancellationToken.None);

        Assert.Equal(PolicyOutcome.Deny, decision.Outcome);
        Assert.Contains("sql_unparsable", decision.RuleIds);
    }

    [Fact]
    public async Task Denies_multiple_statements_when_configured()
    {
        Policy policy = CreatePolicy(denyUnresolvedObjects: false, denyMultipleStatements: true);
        SqlAnalysis analysis = Analysis(
            statementTypes: ["Select", "Select"],
            hasMultipleStatements: true,
            isParsable: true);

        PolicyDecision decision = await _engine.EvaluateAsync(analysis, policy, CancellationToken.None);

        Assert.Equal(PolicyOutcome.Deny, decision.Outcome);
        Assert.Contains("multiple_statements", decision.RuleIds);
    }

    [Fact]
    public async Task Denies_forbidden_operations()
    {
        Policy policy = CreatePolicy(
            denyUnresolvedObjects: false,
            allowedStatementTypes: ["Select"]);
        SqlAnalysis analysis = Analysis(
            statementTypes: ["Delete"],
            tablesWritten: ["users"],
            isParsable: true);

        PolicyDecision decision = await _engine.EvaluateAsync(analysis, policy, CancellationToken.None);

        Assert.Equal(PolicyOutcome.Deny, decision.Outcome);
        Assert.Contains("forbidden_statement_type", decision.RuleIds);
    }

    [Fact]
    public async Task Denies_denied_tables_and_columns_including_cte_subquery_alias_shapes()
    {
        Policy policy = CreatePolicy(
            denyUnresolvedObjects: false,
            deniedTables: ["secrets"],
            deniedColumns: ["ssn"]);

        SqlAnalysis cteShape = Analysis(
            statementTypes: ["Select"],
            tablesRead: ["users", "secrets"],
            columnsRead: ["id"],
            isParsable: true);
        SqlAnalysis columnShape = Analysis(
            statementTypes: ["Select"],
            tablesRead: ["users"],
            columnsRead: ["id", "ssn"],
            isParsable: true);

        PolicyDecision cteDecision = await _engine.EvaluateAsync(cteShape, policy, CancellationToken.None);
        PolicyDecision columnDecision = await _engine.EvaluateAsync(columnShape, policy, CancellationToken.None);

        Assert.Equal(PolicyOutcome.Deny, cteDecision.Outcome);
        Assert.Contains("denied_table", cteDecision.RuleIds);
        Assert.Equal(PolicyOutcome.Deny, columnDecision.Outcome);
        Assert.Contains("denied_column", columnDecision.RuleIds);
        Assert.All(cteDecision.Reasons, r => Assert.DoesNotContain("secrets", r, StringComparison.OrdinalIgnoreCase));
        Assert.All(columnDecision.Reasons, r => Assert.DoesNotContain("ssn", r, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Denied_names_match_across_qualified_and_unqualified_forms_fail_closed()
    {
        Policy unqualifiedPolicy = CreatePolicy(
            denyUnresolvedObjects: false,
            deniedTables: ["secrets"]);
        Policy qualifiedPolicy = CreatePolicy(
            denyUnresolvedObjects: false,
            deniedTables: ["public.secrets"]);

        SqlAnalysis qualifiedQuery = Analysis(
            statementTypes: ["Select"],
            tablesRead: ["public.secrets"],
            isParsable: true);
        SqlAnalysis unqualifiedQuery = Analysis(
            statementTypes: ["Select"],
            tablesRead: ["secrets"],
            isParsable: true);
        SqlAnalysis otherQualifiedQuery = Analysis(
            statementTypes: ["Select"],
            tablesRead: ["private.secrets"],
            isParsable: true);

        PolicyDecision unqualifiedDeny = await _engine.EvaluateAsync(
            qualifiedQuery, unqualifiedPolicy, CancellationToken.None);
        PolicyDecision qualifiedDeny = await _engine.EvaluateAsync(
            unqualifiedQuery, qualifiedPolicy, CancellationToken.None);
        PolicyDecision distinctQualified = await _engine.EvaluateAsync(
            otherQualifiedQuery, qualifiedPolicy, CancellationToken.None);

        Assert.Equal(PolicyOutcome.Deny, unqualifiedDeny.Outcome);
        Assert.Contains("denied_table", unqualifiedDeny.RuleIds);
        Assert.Equal(PolicyOutcome.Deny, qualifiedDeny.Outcome);
        Assert.Contains("denied_table", qualifiedDeny.RuleIds);
        Assert.Equal(PolicyOutcome.Allow, distinctQualified.Outcome);
    }

    [Fact]
    public async Task Denies_denied_columns_in_write_targets()
    {
        Policy policy = CreatePolicy(
            denyUnresolvedObjects: false,
            allowedStatementTypes: ["Insert", "Update"],
            deniedColumns: ["ssn"]);
        SqlAnalysis analysis = Analysis(
            statementTypes: ["Update"],
            tablesWritten: ["users"],
            columnsWritten: ["ssn"],
            isParsable: true);

        PolicyDecision decision = await _engine.EvaluateAsync(analysis, policy, CancellationToken.None);

        Assert.Equal(PolicyOutcome.Deny, decision.Outcome);
        Assert.Contains("denied_column", decision.RuleIds);
    }

    [Fact]
    public async Task Denies_unknown_functions_when_allow_list_non_empty()
    {
        Policy policy = CreatePolicy(
            denyUnresolvedObjects: false,
            allowedFunctions: ["count"]);
        SqlAnalysis analysis = Analysis(
            statementTypes: ["Select"],
            tablesRead: ["users"],
            functions: ["count", "pg_sleep"],
            isParsable: true);

        PolicyDecision decision = await _engine.EvaluateAsync(analysis, policy, CancellationToken.None);

        Assert.Equal(PolicyOutcome.Deny, decision.Outcome);
        Assert.Contains("unknown_function", decision.RuleIds);
        Assert.All(decision.Reasons, r => Assert.DoesNotContain("pg_sleep", r, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Denies_functions_when_allow_list_empty()
    {
        Policy policy = CreatePolicy(
            denyUnresolvedObjects: false,
            allowedFunctions: []);
        SqlAnalysis analysis = Analysis(
            statementTypes: ["Select"],
            tablesRead: ["users"],
            functions: ["lower"],
            isParsable: true);

        PolicyDecision decision = await _engine.EvaluateAsync(analysis, policy, CancellationToken.None);

        Assert.Equal(PolicyOutcome.Deny, decision.Outcome);
        Assert.Contains("unknown_function", decision.RuleIds);
    }

    [Theory]
    [InlineData("sav_scope.SAV_SAFE_FN", "sav_scope.sav_safe_fn", PolicyOutcome.Deny)]
    [InlineData("SAV_SCOPE.sav_safe_fn", "sav_scope.sav_safe_fn", PolicyOutcome.Deny)]
    [InlineData("sav_scope.sav_safe_fn", "sav_scope.SAV_SAFE_FN", PolicyOutcome.Deny)]
    [InlineData("sav_scope.SAV_SAFE_FN", "sav_scope.SAV_SAFE_FN", PolicyOutcome.Allow)]
    [InlineData("SAV_SCOPE.sav_safe_fn", "SAV_SCOPE.sav_safe_fn", PolicyOutcome.Allow)]
    [InlineData("sav_scope.sav_safe_fn", "sav_scope.sav_safe_fn", PolicyOutcome.Allow)]
    public async Task Function_authorization_uses_exact_parser_normalized_identity(
        string function, string allowed, PolicyOutcome expected)
    {
        PolicyDecision decision = await _engine.EvaluateAsync(
            Analysis(["Select"], true, functions: [function]),
            CreatePolicy(false, allowedFunctions: [allowed]), CancellationToken.None);

        Assert.Equal(expected, decision.Outcome);
        Assert.Equal(expected == PolicyOutcome.Deny ? ["unknown_function"] : Array.Empty<string>(), decision.RuleIds);
        Assert.Equal(decision.RuleIds, decision.Reasons);
    }

    [Fact]
    public async Task Denies_unresolved_objects_when_configured()
    {
        Policy policy = CreatePolicy(denyUnresolvedObjects: true);
        SqlAnalysis analysis = Analysis(
            statementTypes: ["Select"],
            tablesRead: ["users"],
            unresolvedObjects: ["users"],
            isParsable: true);

        PolicyDecision decision = await _engine.EvaluateAsync(analysis, policy, CancellationToken.None);

        Assert.Equal(PolicyOutcome.Deny, decision.Outcome);
        Assert.Contains("unresolved_object", decision.RuleIds);
    }

    [Fact]
    public async Task Denies_update_or_delete_without_predicate_when_configured()
    {
        Policy policy = CreatePolicy(
            denyUnresolvedObjects: false,
            allowedStatementTypes: ["Update", "Delete"],
            denyUpdateDeleteWithoutPredicate: true);

        SqlAnalysis update = Analysis(
            statementTypes: ["Update"],
            tablesWritten: ["users"],
            riskCodes: ["missing_predicate"],
            isParsable: true);
        SqlAnalysis delete = Analysis(
            statementTypes: ["Delete"],
            tablesWritten: ["users"],
            riskCodes: ["missing_predicate"],
            isParsable: true);

        PolicyDecision updateDecision = await _engine.EvaluateAsync(update, policy, CancellationToken.None);
        PolicyDecision deleteDecision = await _engine.EvaluateAsync(delete, policy, CancellationToken.None);

        Assert.Equal(PolicyOutcome.Deny, updateDecision.Outcome);
        Assert.Contains("missing_predicate", updateDecision.RuleIds);
        Assert.Equal(PolicyOutcome.Deny, deleteDecision.Outcome);
        Assert.Contains("missing_predicate", deleteDecision.RuleIds);
    }

    [Fact]
    public async Task Denies_unsupported_construct_risk()
    {
        Policy policy = CreatePolicy(denyUnresolvedObjects: false);
        SqlAnalysis analysis = Analysis(
            statementTypes: ["Select"],
            tablesRead: ["users"],
            riskCodes: ["unsupported_construct"],
            isParsable: true);

        PolicyDecision decision = await _engine.EvaluateAsync(analysis, policy, CancellationToken.None);

        Assert.Equal(PolicyOutcome.Deny, decision.Outcome);
        Assert.Contains("unsupported_construct", decision.RuleIds);
    }

    [Fact]
    public async Task Returns_review_for_needs_review_risk()
    {
        Policy policy = CreatePolicy(denyUnresolvedObjects: false);
        SqlAnalysis analysis = Analysis(
            statementTypes: ["Select"],
            tablesRead: ["users"],
            riskCodes: ["needs_review"],
            isParsable: true);

        PolicyDecision decision = await _engine.EvaluateAsync(analysis, policy, CancellationToken.None);

        Assert.Equal(PolicyOutcome.Review, decision.Outcome);
        Assert.Contains("needs_review", decision.RuleIds);
    }

    [Fact]
    public async Task Reasons_are_redacted_machine_codes_only()
    {
        Policy policy = CreatePolicy(
            denyUnresolvedObjects: false,
            deniedTables: ["users"]);
        SqlAnalysis analysis = Analysis(
            statementTypes: ["Select"],
            tablesRead: ["users"],
            isParsable: true,
            normalizedSql: "SELECT id FROM users WHERE email = 'canary@example.invalid'");

        PolicyDecision decision = await _engine.EvaluateAsync(analysis, policy, CancellationToken.None);

        Assert.Equal(PolicyOutcome.Deny, decision.Outcome);
        Assert.All(decision.Reasons, r =>
        {
            Assert.DoesNotContain("canary@", r, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("users", r, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("SELECT", r, StringComparison.OrdinalIgnoreCase);
        });
    }

    private static Policy CreatePolicy(
        bool denyUnresolvedObjects,
        bool denyMultipleStatements = true,
        bool denyUpdateDeleteWithoutPredicate = true,
        IReadOnlyList<string>? allowedStatementTypes = null,
        IReadOnlyList<string>? deniedTables = null,
        IReadOnlyList<string>? deniedColumns = null,
        IReadOnlyList<string>? allowedFunctions = null)
    {
        return new Policy(
            id: "test-policy",
            version: "1",
            allowedStatementTypes: allowedStatementTypes ?? ["Select"],
            deniedTables: deniedTables ?? [],
            deniedColumns: deniedColumns ?? [],
            allowedFunctions: allowedFunctions ?? [],
            denyUnresolvedObjects: denyUnresolvedObjects,
            denyMultipleStatements: denyMultipleStatements,
            denyUpdateDeleteWithoutPredicate: denyUpdateDeleteWithoutPredicate,
            maxCostBucket: "high",
            forbiddenPlanNodes: [],
            disclosure: new DisclosureProfile(
                Name: "strict",
                IncludePlanSummary: false,
                IncludeObjectNames: false,
                IncludeTimings: false,
                IncludeRowCounts: false));
    }

    private static SqlAnalysis Analysis(
        IReadOnlyList<string> statementTypes,
        bool isParsable,
        IReadOnlyList<string>? tablesRead = null,
        IReadOnlyList<string>? tablesWritten = null,
        IReadOnlyList<string>? columnsRead = null,
        IReadOnlyList<string>? columnsWritten = null,
        IReadOnlyList<string>? functions = null,
        bool hasMultipleStatements = false,
        bool hasDynamicSql = false,
        IReadOnlyList<string>? unresolvedObjects = null,
        IReadOnlyList<string>? riskCodes = null,
        string normalizedSql = "SELECT 1")
    {
        SqlIr ir = new(
            dialect: "postgresql",
            statementTypes: statementTypes,
            tablesRead: tablesRead ?? [],
            tablesWritten: tablesWritten ?? [],
            columnsRead: columnsRead ?? [],
            columnsWritten: columnsWritten ?? [],
            functions: functions ?? [],
            hasMultipleStatements: hasMultipleStatements,
            hasDynamicSql: hasDynamicSql,
            unresolvedObjects: unresolvedObjects ?? [],
            riskCodes: riskCodes ?? [],
            normalizedSql: normalizedSql,
            fingerprint: "fp");
        return new SqlAnalysis(ir, isParsable);
    }
}
