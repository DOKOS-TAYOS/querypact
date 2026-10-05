using Sav.Application.Abstractions;
using Sav.Domain.Analysis;
using Sav.Domain.Contracts;
using Sav.Domain.Decisions;
using Sav.Domain.Errors;
using Sav.Domain.Execution;
using Sav.Domain.Properties;
using Sav.Domain.Schema;
using Sav.Infrastructure.Postgres.Oracle;
using Sav.Infrastructure.Postgres.Redaction;

namespace Sav.Infrastructure.Postgres.Tests.Oracle;

public sealed class SchemaInvariantPropertyTests
{
    private readonly MinimalDisclosure _disclosure = new();

    [Fact]
    public async Task Passes_when_required_relations_counts_and_constraints_hold()
    {
        SchemaSnapshot before = CreateBaseline();
        SchemaSnapshot after = CreateBaseline();

        PropertyResult result = await EvaluateAsync(
            before,
            after,
            new SchemaInvariantSpec(
            [
                new SchemaInvariantRequirement("orders", "r"),
                new SchemaInvariantRequirement("order_items", "r"),
            ]));

        Assert.Equal(PropertyStatus.Pass, result.Status);
        Assert.Null(result.RedactedDetail);
    }

    [Fact]
    public async Task Passes_for_supported_uppercase_sequence_relkind()
    {
        SchemaSnapshot snapshot = new(
            "public",
            new Dictionary<string, long> { ["S"] = 1 },
            new Dictionary<string, string> { ["public.order_seq"] = "digest-seq-v1" },
            new Dictionary<string, bool>(),
            relationKindByName: new Dictionary<string, string> { ["public.order_seq"] = "S" });

        PropertyResult result = await EvaluateAsync(
            snapshot,
            snapshot,
            new SchemaInvariantSpec([new SchemaInvariantRequirement("order_seq", "S")]));

        Assert.Equal(PropertyStatus.Pass, result.Status);
        Assert.Null(result.RedactedDetail);
    }

    [Theory]
    [InlineData("i")]
    [InlineData("I")]
    [InlineData("x")]
    public async Task Unsupported_relkind_returns_contract_invalid(string relkind)
    {
        SchemaSnapshot snapshot = new(
            "public",
            new Dictionary<string, long> { [relkind] = 1 },
            new Dictionary<string, string> { ["public.orders_idx"] = "digest-index-v1" },
            new Dictionary<string, bool>());

        PropertyResult result = await EvaluateAsync(
            snapshot,
            snapshot,
            new SchemaInvariantSpec([new SchemaInvariantRequirement("orders_idx", relkind)]));

        Assert.Equal(PropertyStatus.Error, result.Status);
        Assert.Equal(SavErrorCode.ContractInvalid, result.RedactedDetail);
    }

    [Fact]
    public async Task Fails_when_relation_digest_changes()
    {
        SchemaSnapshot before = CreateBaseline();
        SchemaSnapshot after = new(
            before.SchemaName,
            before.RelationCountByRelkind,
            new Dictionary<string, string>
            {
                ["public.orders"] = "digest-orders-MUTATED",
                ["public.order_items"] = "digest-items-v1",
            },
            before.ConstraintExistsByName,
            relationKindByName: before.RelationKindByName);

        PropertyResult result = await EvaluateAsync(
            before,
            after,
            new SchemaInvariantSpec([new SchemaInvariantRequirement("orders", "r")]));

        Assert.Equal(PropertyStatus.Fail, result.Status);
        Assert.Equal(SavErrorCode.SchemaInvariantFailed, result.RedactedDetail);
    }

    [Fact]
    public async Task Fails_when_required_relation_is_created_during_migration()
    {
        SchemaSnapshot before = new(
            "public",
            new Dictionary<string, long> { ["r"] = 1 },
            new Dictionary<string, string> { ["public.other_table"] = "digest-other-v1" },
            new Dictionary<string, bool>(),
            relationKindByName: new Dictionary<string, string> { ["public.other_table"] = "r" });
        SchemaSnapshot after = new(
            "public",
            new Dictionary<string, long> { ["r"] = 1 },
            new Dictionary<string, string> { ["public.orders"] = "digest-orders-v1" },
            new Dictionary<string, bool>(),
            relationKindByName: new Dictionary<string, string> { ["public.orders"] = "r" });

        PropertyResult result = await EvaluateAsync(
            before,
            after,
            new SchemaInvariantSpec([new SchemaInvariantRequirement("orders", "r")]));

        Assert.Equal(PropertyStatus.Fail, result.Status);
        Assert.Equal(SavErrorCode.SchemaInvariantFailed, result.RedactedDetail);
    }

    [Fact]
    public async Task Fails_when_same_named_constraint_definition_changes()
    {
        SchemaSnapshot before = CreateBaseline();
        SchemaSnapshot after = new(
            before.SchemaName,
            before.RelationCountByRelkind,
            before.RelationDigestByName,
            before.ConstraintExistsByName,
            new Dictionary<string, string>
            {
                ["public.orders.orders_pkey"] = "constraint-orders-MUTATED",
                ["public.order_items.order_items_orders_fkey"] = "constraint-items-v1",
            },
            before.RelationKindByName);

        PropertyResult result = await EvaluateAsync(
            before,
            after,
            new SchemaInvariantSpec([new SchemaInvariantRequirement("orders", "r")]));

        Assert.Equal(PropertyStatus.Fail, result.Status);
        Assert.Equal(SavErrorCode.SchemaInvariantFailed, result.RedactedDetail);
    }

    [Fact]
    public async Task Fails_when_relkind_count_drifts()
    {
        SchemaSnapshot before = CreateBaseline();
        Dictionary<string, long> counts = before.RelationCountByRelkind.ToDictionary(
            static p => p.Key,
            static p => p.Value);
        counts["r"] = 99;
        SchemaSnapshot after = new(
            before.SchemaName,
            counts,
            before.RelationDigestByName,
            before.ConstraintExistsByName,
            relationKindByName: before.RelationKindByName);

        PropertyResult result = await EvaluateAsync(
            before,
            after,
            new SchemaInvariantSpec([new SchemaInvariantRequirement("orders", "r")]));

        Assert.Equal(PropertyStatus.Fail, result.Status);
        Assert.Equal(SavErrorCode.SchemaInvariantFailed, result.RedactedDetail);
    }

    [Fact]
    public async Task Fails_when_required_relation_has_different_relkind_even_when_global_count_matches()
    {
        SchemaSnapshot snapshot = new(
            "public",
            new Dictionary<string, long> { ["r"] = 1, ["v"] = 1 },
            new Dictionary<string, string>
            {
                ["public.orders"] = "same-shape-digest",
                ["public.other_table"] = "other-digest",
            },
            new Dictionary<string, bool>(),
            relationKindByName: new Dictionary<string, string>
            {
                ["public.orders"] = "v",
                ["public.other_table"] = "r",
            });

        PropertyResult result = await EvaluateAsync(
            snapshot,
            snapshot,
            new SchemaInvariantSpec([new SchemaInvariantRequirement("orders", "r")]));

        Assert.Equal(PropertyStatus.Fail, result.Status);
        Assert.Equal(SavErrorCode.SchemaInvariantFailed, result.RedactedDetail);
    }

    [Fact]
    public async Task Real_alias_returns_property_environment_forbidden()
    {
        SchemaSnapshot snap = CreateBaseline();
        PropertyOracle oracle = new(_disclosure.Redactor);
        IReadOnlyList<PropertyResult> results = await oracle.EvaluateAsync(
            new PropertyEvaluationRequest(
                ExecutionEnvironment.RealReadOnlyAlias,
                DummyIr(),
                [new SchemaInvariantSpec([new SchemaInvariantRequirement("orders", "r")])],
                null,
                null,
                null,
                null,
                null,
                snap,
                snap,
                _disclosure.Profile),
            CancellationToken.None);

        PropertyResult result = Assert.Single(results);
        Assert.Equal(PropertyStatus.Error, result.Status);
        Assert.Equal(SavErrorCode.PropertyEnvironmentForbidden, result.RedactedDetail);
    }

    private async Task<PropertyResult> EvaluateAsync(
        SchemaSnapshot before,
        SchemaSnapshot after,
        SchemaInvariantSpec spec)
    {
        PropertyOracle oracle = new(_disclosure.Redactor);
        IReadOnlyList<PropertyResult> results = await oracle.EvaluateAsync(
            new PropertyEvaluationRequest(
                ExecutionEnvironment.EphemeralContainer,
                DummyIr(),
                [spec],
                null,
                null,
                null,
                null,
                null,
                before,
                after,
                _disclosure.Profile),
            CancellationToken.None);

        return Assert.Single(results);
    }

    private static SchemaSnapshot CreateBaseline()
    {
        return new SchemaSnapshot(
            "public",
            new Dictionary<string, long> { ["r"] = 2, ["i"] = 1 },
            new Dictionary<string, string>
            {
                ["public.orders"] = "digest-orders-v1",
                ["public.order_items"] = "digest-items-v1",
            },
            new Dictionary<string, bool>
            {
                ["orders_pkey"] = true,
                ["order_items_orders_fkey"] = true,
            },
            new Dictionary<string, string>
            {
                ["public.orders.orders_pkey"] = "constraint-orders-v1",
                ["public.order_items.order_items_orders_fkey"] = "constraint-items-v1",
            },
            new Dictionary<string, string>
            {
                ["public.orders"] = "r",
                ["public.order_items"] = "r",
            });
    }

    private static SqlIr DummyIr()
    {
        return new SqlIr(
            "postgresql",
            ["Select"],
            [],
            [],
            [],
            [],
            [],
            false,
            false,
            [],
            [],
            "SELECT 1",
            "schema-inv-fp");
    }

    private sealed class MinimalDisclosure
    {
        public MinimalStrictRedactor Redactor { get; } = new();

        public Sav.Domain.Policies.DisclosureProfile Profile { get; } = new(
            "strict",
            IncludePlanSummary: false,
            IncludeObjectNames: false,
            IncludeTimings: false,
            IncludeRowCounts: false);
    }
}
