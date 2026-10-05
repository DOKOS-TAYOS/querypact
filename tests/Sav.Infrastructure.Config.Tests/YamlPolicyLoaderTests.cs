using Sav.Domain.Errors;
using Sav.Domain.Policies;

namespace Sav.Infrastructure.Config.Tests;

public sealed class YamlPolicyLoaderTests
{
    private readonly YamlPolicyLoader _loader = new();

    [Fact]
    public async Task Loads_valid_basic_policy_with_max_cost_and_forbidden_nodes()
    {
        string path = FixturePath.Resolve("policies", "valid-basic.yaml");

        Policy policy = await _loader.LoadAsync(path, CancellationToken.None);

        Assert.Equal("demo-policy", policy.Id);
        Assert.Equal("high", policy.MaxCostBucket);
        Assert.Empty(policy.ForbiddenPlanNodes);
        Assert.Contains("Select", policy.AllowedStatementTypes);
    }

    [Fact]
    public async Task Rejects_missing_max_cost_bucket_with_policy_invalid()
    {
        string path = FixturePath.Resolve("policies", "invalid-missing-field.yaml");

        SavException ex = await Assert.ThrowsAsync<SavException>(
            () => _loader.LoadAsync(path, CancellationToken.None));

        Assert.Equal(SavErrorCode.PolicyInvalid, ex.Code);
        Assert.StartsWith("policy_invalid:", ex.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("Select", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Rejects_unknown_cost_bucket_token()
    {
        string path = WriteTempYaml(
            """
            id: demo-policy
            version: "1"
            allowedStatementTypes:
              - Select
            deniedTables: []
            deniedColumns: []
            allowedFunctions: []
            denyUnresolvedObjects: true
            denyMultipleStatements: true
            denyUpdateDeleteWithoutPredicate: true
            maxCostBucket: planetary
            forbiddenPlanNodes: []
            disclosure:
              name: strict
              includePlanSummary: false
              includeObjectNames: false
              includeTimings: false
              includeRowCounts: false
            """);

        SavException ex = await Assert.ThrowsAsync<SavException>(
            () => _loader.LoadAsync(path, CancellationToken.None));

        Assert.Equal(SavErrorCode.PolicyInvalid, ex.Code);
        Assert.DoesNotContain("planetary", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Rejects_unknown_policy_field_instead_of_ignoring_it()
    {
        string path = WriteTempYaml(
            """
            id: demo-policy
            version: "1"
            allowedStatementTypes:
              - Select
            deniedTable: []
            deniedTables: []
            deniedColumns: []
            allowedFunctions: []
            denyUnresolvedObjects: true
            denyMultipleStatements: true
            denyUpdateDeleteWithoutPredicate: true
            maxCostBucket: high
            forbiddenPlanNodes: []
            disclosure:
              name: strict
              includePlanSummary: false
              includeObjectNames: false
              includeTimings: false
              includeRowCounts: false
            """);

        SavException ex = await Assert.ThrowsAsync<SavException>(
            () => _loader.LoadAsync(path, CancellationToken.None));

        Assert.Equal(SavErrorCode.PolicyInvalid, ex.Code);
    }

    [Fact]
    public async Task Normalizes_whitespace_in_negative_policy_lists()
    {
        string path = WriteTempYaml(
            """
            id: demo-policy
            version: "1"
            allowedStatementTypes:
              - Select
            deniedTables:
              - " users "
            deniedColumns:
              - " ssn "
            allowedFunctions: []
            denyUnresolvedObjects: true
            denyMultipleStatements: true
            denyUpdateDeleteWithoutPredicate: true
            maxCostBucket: high
            forbiddenPlanNodes:
              - " Seq Scan "
            disclosure:
              name: strict
              includePlanSummary: false
              includeObjectNames: false
              includeTimings: false
              includeRowCounts: false
            """);

        Policy policy = await _loader.LoadAsync(path, CancellationToken.None);

        Assert.Equal(["users"], policy.DeniedTables);
        Assert.Equal(["ssn"], policy.DeniedColumns);
        Assert.Equal(["Seq Scan"], policy.ForbiddenPlanNodes);
    }

    [Fact]
    public async Task Rejects_duplicate_policy_keys()
    {
        string path = WriteTempYaml(
            """
            id: demo-policy
            version: "1"
            allowedStatementTypes:
              - Select
            deniedTables: []
            deniedColumns: []
            allowedFunctions: []
            denyUnresolvedObjects: true
            denyMultipleStatements: true
            denyMultipleStatements: false
            denyUpdateDeleteWithoutPredicate: true
            maxCostBucket: high
            forbiddenPlanNodes: []
            disclosure:
              name: strict
              includePlanSummary: false
              includeObjectNames: false
              includeTimings: false
              includeRowCounts: false
            """);

        SavException ex = await Assert.ThrowsAsync<SavException>(
            () => _loader.LoadAsync(path, CancellationToken.None));

        Assert.Equal(SavErrorCode.PolicyInvalid, ex.Code);
    }

    [Fact]
    public async Task Rejects_missing_security_relevant_policy_lists()
    {
        string path = WriteTempYaml(
            """
            id: demo-policy
            version: "1"
            allowedStatementTypes:
              - Select
            deniedTables: []
            deniedColumns: []
            denyUnresolvedObjects: true
            denyMultipleStatements: true
            denyUpdateDeleteWithoutPredicate: true
            maxCostBucket: high
            forbiddenPlanNodes: []
            disclosure:
              name: strict
              includePlanSummary: false
              includeObjectNames: false
              includeTimings: false
              includeRowCounts: false
            """);

        SavException ex = await Assert.ThrowsAsync<SavException>(
            () => _loader.LoadAsync(path, CancellationToken.None));

        Assert.Equal(SavErrorCode.PolicyInvalid, ex.Code);
        Assert.Contains("allowedFunctions is required", ex.Message, StringComparison.Ordinal);
    }

    private static string WriteTempYaml(string contents)
    {
        string path = Path.Combine(Path.GetTempPath(), "sav-policy-" + Guid.NewGuid().ToString("N") + ".yaml");
        File.WriteAllText(path, contents);
        return path;
    }
}
