using Sav.Domain.Contracts;
using Sav.Domain.Errors;

namespace Sav.Infrastructure.Config.Tests;

public sealed class YamlContractLoaderTests
{
    private readonly YamlContractLoader _loader = new();

    [Fact]
    public async Task Loads_valid_basic_contract()
    {
        string path = FixturePath.Resolve("contracts", "valid-basic.yaml");

        Contract contract = await _loader.LoadAsync(path, CancellationToken.None);

        Assert.Equal("demo-contract", contract.Id);
        Assert.Single(contract.RequiredProperties);
        Assert.IsType<QuerySucceedsSpec>(contract.RequiredProperties[0]);
    }

    [Fact]
    public async Task Loads_mvp_a_query_succeeds_and_empty_result_joint_fixture()
    {
        string path = FixturePath.Resolve("contracts", "valid-mvp-a-query-succeeds-empty-result.yaml");

        Contract contract = await _loader.LoadAsync(path, CancellationToken.None);

        Assert.Equal(2, contract.RequiredProperties.Count);
        Assert.IsType<QuerySucceedsSpec>(contract.RequiredProperties[0]);
        Assert.IsType<EmptyResultSpec>(contract.RequiredProperties[1]);
    }

    [Fact]
    public async Task Loads_mvp_b_unique_and_non_null_fixture()
    {
        string path = FixturePath.Resolve("contracts", "valid-mvp-b-unique-nonnull.yaml");

        Contract contract = await _loader.LoadAsync(path, CancellationToken.None);

        Assert.Equal(2, contract.RequiredProperties.Count);
        UniqueSpec unique = Assert.IsType<UniqueSpec>(contract.RequiredProperties[0]);
        NonNullSpec nonNull = Assert.IsType<NonNullSpec>(contract.RequiredProperties[1]);
        Assert.Equal("code", unique.Column);
        Assert.Equal("code", nonNull.Column);
    }

    [Fact]
    public async Task Loads_mvp_b_equivalence_and_affected_rows_fixture()
    {
        string path = FixturePath.Resolve("contracts", "valid-mvp-b-equivalence-dml.yaml");

        Contract contract = await _loader.LoadAsync(path, CancellationToken.None);

        Assert.Equal(2, contract.RequiredProperties.Count);
        Assert.IsType<QueryEquivalentSpec>(contract.RequiredProperties[0]);
        AffectedRowsSpec affected = Assert.IsType<AffectedRowsSpec>(contract.RequiredProperties[1]);
        Assert.Equal(0, affected.MinInclusive);
        Assert.Equal(100, affected.MaxInclusive);
    }

    [Fact]
    public async Task Loads_mvp_b_schema_invariant_and_orphans_fixture()
    {
        string path = FixturePath.Resolve("contracts", "valid-mvp-b-schema-orphans.yaml");

        Contract contract = await _loader.LoadAsync(path, CancellationToken.None);

        Assert.Equal(2, contract.RequiredProperties.Count);
        SchemaInvariantSpec schema = Assert.IsType<SchemaInvariantSpec>(contract.RequiredProperties[0]);
        Assert.Equal(2, schema.Requirements.Count);
        Assert.Equal("orders", schema.Requirements[0].RelationName);
        NoNewOrphansSpec orphans = Assert.IsType<NoNewOrphansSpec>(contract.RequiredProperties[1]);
        Assert.Equal("order_items", orphans.ChildTable);
        Assert.Equal("order_id", orphans.ChildKey);
    }

    [Fact]
    public async Task Loads_schema_invariant_sequence_relkind()
    {
        string path = WriteTempYaml(
            """
            id: sequence-contract
            version: "1"
            requiredProperties:
              - name: schema_invariant
                requirements:
                  - relationName: order_seq
                    relkind: S
            disclosure:
              name: strict
              includePlanSummary: false
              includeObjectNames: false
              includeTimings: false
              includeRowCounts: false
            """);

        Contract contract = await _loader.LoadAsync(path, CancellationToken.None);

        SchemaInvariantSpec schema = Assert.IsType<SchemaInvariantSpec>(Assert.Single(contract.RequiredProperties));
        Assert.Equal("S", Assert.Single(schema.Requirements).Relkind);
    }

    [Theory]
    [InlineData("i")]
    [InlineData("I")]
    [InlineData("x")]
    public async Task Rejects_unsupported_schema_invariant_relkind(string relkind)
    {
        string path = WriteTempYaml(
            $"""
            id: bad
            version: "1"
            requiredProperties:
              - name: schema_invariant
                requirements:
                  - relationName: orders_idx
                    relkind: {relkind}
            disclosure:
              name: strict
              includePlanSummary: false
              includeObjectNames: false
              includeTimings: false
              includeRowCounts: false
            """);

        SavException ex = await Assert.ThrowsAsync<SavException>(
            () => _loader.LoadAsync(path, CancellationToken.None));

        Assert.Equal(SavErrorCode.ContractInvalid, ex.Code);
    }

    [Fact]
    public async Task Rejects_affected_rows_with_unknown_optional_field()
    {
        string path = WriteTempYaml(
            """
            id: bad
            version: "1"
            requiredProperties:
              - name: affected_rows
                minInclusive: 0
                maxInclusve: 10
            disclosure:
              name: strict
              includePlanSummary: false
              includeObjectNames: false
              includeTimings: false
              includeRowCounts: false
            """);

        SavException ex = await Assert.ThrowsAsync<SavException>(
            () => _loader.LoadAsync(path, CancellationToken.None));

        Assert.Equal(SavErrorCode.ContractInvalid, ex.Code);
    }

    [Fact]
    public async Task Rejects_schema_invariant_requirement_with_unknown_field()
    {
        string path = WriteTempYaml(
            """
            id: bad
            version: "1"
            requiredProperties:
              - name: schema_invariant
                requirements:
                  - relationName: orders
                    relknd: r
            disclosure:
              name: strict
              includePlanSummary: false
              includeObjectNames: false
              includeTimings: false
              includeRowCounts: false
            """);

        SavException ex = await Assert.ThrowsAsync<SavException>(
            () => _loader.LoadAsync(path, CancellationToken.None));

        Assert.Equal(SavErrorCode.ContractInvalid, ex.Code);
    }

    [Fact]
    public async Task Rejects_unknown_top_level_contract_field()
    {
        string path = WriteTempYaml(
            """
            id: bad
            version: "1"
            requiredProperties:
              - name: query_succeeds
            unexpectedField: true
            disclosure:
              name: strict
              includePlanSummary: false
              includeObjectNames: false
              includeTimings: false
              includeRowCounts: false
            """);

        SavException ex = await Assert.ThrowsAsync<SavException>(
            () => _loader.LoadAsync(path, CancellationToken.None));

        Assert.Equal(SavErrorCode.ContractInvalid, ex.Code);
    }

    [Fact]
    public async Task Rejects_duplicate_contract_keys()
    {
        string path = WriteTempYaml(
            """
            id: bad
            version: "1"
            version: "2"
            requiredProperties:
              - name: query_succeeds
            disclosure:
              name: strict
              includePlanSummary: false
              includeObjectNames: false
              includeTimings: false
              includeRowCounts: false
            """);

        SavException ex = await Assert.ThrowsAsync<SavException>(
            () => _loader.LoadAsync(path, CancellationToken.None));

        Assert.Equal(SavErrorCode.ContractInvalid, ex.Code);
    }

    [Theory]
    [InlineData(10L, 5L)]
    [InlineData(0L, -1L)]
    public async Task Rejects_affected_rows_with_max_below_min_at_load_time(
        long minInclusive,
        long maxInclusive)
    {
        string path = WriteTempYaml(
            $"""
            id: bad
            version: "1"
            requiredProperties:
              - name: affected_rows
                minInclusive: {minInclusive}
                maxInclusive: {maxInclusive}
            disclosure:
              name: strict
              includePlanSummary: false
              includeObjectNames: false
              includeTimings: false
              includeRowCounts: false
            """);

        SavException ex = await Assert.ThrowsAsync<SavException>(
            () => _loader.LoadAsync(path, CancellationToken.None));

        Assert.Equal(SavErrorCode.ContractInvalid, ex.Code);
        Assert.DoesNotContain(path, ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Accepts_affected_rows_with_equal_inclusive_bounds()
    {
        string path = WriteTempYaml(
            """
            id: valid
            version: "1"
            requiredProperties:
              - name: affected_rows
                minInclusive: 5
                maxInclusive: 5
            disclosure:
              name: strict
              includePlanSummary: false
              includeObjectNames: false
              includeTimings: false
              includeRowCounts: false
            """);

        Contract contract = await _loader.LoadAsync(path, CancellationToken.None);

        AffectedRowsSpec spec = Assert.IsType<AffectedRowsSpec>(Assert.Single(contract.RequiredProperties));
        Assert.Equal(5, spec.MinInclusive);
        Assert.Equal(5, spec.MaxInclusive);
    }

    [Fact]
    public async Task Rejects_affected_rows_without_min_inclusive()
    {
        string path = WriteTempYaml(
            """
            id: bad
            version: "1"
            requiredProperties:
              - name: affected_rows
            disclosure:
              name: strict
              includePlanSummary: false
              includeObjectNames: false
              includeTimings: false
              includeRowCounts: false
            """);

        SavException ex = await Assert.ThrowsAsync<SavException>(
            () => _loader.LoadAsync(path, CancellationToken.None));

        Assert.Equal(SavErrorCode.ContractInvalid, ex.Code);
    }

    [Fact]
    public async Task Rejects_string_only_property_lists_with_contract_invalid()
    {
        string path = WriteTempYaml(
            """
            id: bad
            version: "1"
            requiredProperties:
              - unique
            disclosure:
              name: strict
              includePlanSummary: false
              includeObjectNames: false
              includeTimings: false
              includeRowCounts: false
            """);

        SavException ex = await Assert.ThrowsAsync<SavException>(
            () => _loader.LoadAsync(path, CancellationToken.None));

        Assert.Equal(SavErrorCode.ContractInvalid, ex.Code);
        Assert.DoesNotContain("unique", ex.Message, StringComparison.OrdinalIgnoreCase); // optional: may mention token
        Assert.DoesNotContain(path, ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Rejects_unknown_property_name_with_contract_invalid()
    {
        string path = WriteTempYaml(
            """
            id: bad
            version: "1"
            requiredProperties:
              - name: not_a_real_property
            disclosure:
              name: strict
              includePlanSummary: false
              includeObjectNames: false
              includeTimings: false
              includeRowCounts: false
            """);

        SavException ex = await Assert.ThrowsAsync<SavException>(
            () => _loader.LoadAsync(path, CancellationToken.None));

        Assert.Equal(SavErrorCode.ContractInvalid, ex.Code);
        Assert.StartsWith("contract_invalid:", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Rejects_empty_required_properties_with_contract_invalid()
    {
        string path = WriteTempYaml(
            """
            id: bad
            version: "1"
            requiredProperties: []
            disclosure:
              name: strict
              includePlanSummary: false
              includeObjectNames: false
              includeTimings: false
              includeRowCounts: false
            """);

        SavException ex = await Assert.ThrowsAsync<SavException>(
            () => _loader.LoadAsync(path, CancellationToken.None));

        Assert.Equal(SavErrorCode.ContractInvalid, ex.Code);
        Assert.Contains("requiredProperties must not be empty", ex.Message, StringComparison.Ordinal);
    }

    private static string WriteTempYaml(string contents)
    {
        string path = Path.Combine(Path.GetTempPath(), "sav-contract-" + Guid.NewGuid().ToString("N") + ".yaml");
        File.WriteAllText(path, contents);
        return path;
    }
}
