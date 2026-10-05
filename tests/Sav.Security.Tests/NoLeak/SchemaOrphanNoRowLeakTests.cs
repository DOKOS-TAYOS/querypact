using Sav.Application.Abstractions;
using Sav.Domain.Analysis;
using Sav.Domain.Contracts;
using Sav.Domain.Decisions;
using Sav.Domain.Errors;
using Sav.Domain.Execution;
using Sav.Domain.Properties;
using Sav.Domain.Schema;
using Sav.Infrastructure.Postgres.Oracle;
using Sav.Infrastructure.Postgres.Oracle.Properties;
using Sav.Infrastructure.Postgres.Tests.Fixtures;

namespace Sav.Security.Tests.NoLeak;

[Collection(nameof(PostgresRoCollection))]
public sealed class SchemaOrphanNoRowLeakTests
{
    private const string Canary = "CANARY_ORPHAN_do_not_egress@example.invalid";

    private readonly PostgresRoFixture _fixture;

    public SchemaOrphanNoRowLeakTests(PostgresRoFixture fixture)
    {
        _fixture = fixture;
    }

    [Fact]
    public async Task Orphan_fail_never_leaks_key_values_or_count()
    {
        await _fixture.ExecuteAdminAsync(
            $"""
            CREATE TABLE IF NOT EXISTS public.leak_parent (
              id text PRIMARY KEY
            );
            CREATE TABLE IF NOT EXISTS public.leak_child (
              id int PRIMARY KEY,
              parent_id text NOT NULL
            );
            TRUNCATE public.leak_child, public.leak_parent;
            INSERT INTO public.leak_parent(id) VALUES ('ok');
            INSERT INTO public.leak_child(id, parent_id) VALUES
              (1, 'ok'),
              (2, '{Canary}');
            """);

        EphemeralSessionFactory ephemeralFactory = new(_fixture.Redactor, _fixture.StrictDisclosure);
        PropertyOracle oracle = new(
            _fixture.Redactor,
            ephemeralSessionFactory: ephemeralFactory,
            ephemeralConnectionString: _fixture.AdminConnectionString);

        IReadOnlyList<PropertyResult> results = await oracle.EvaluateAsync(
            new PropertyEvaluationRequest(
                ExecutionEnvironment.EphemeralContainer,
                new SqlIr(
                    "postgresql",
                    ["Select"],
                    ["leak_parent", "leak_child"],
                    [],
                    ["id", "parent_id"],
                    [],
                    [],
                    false,
                    false,
                    [],
                    [],
                    "SELECT 1",
                    "orphan-leak-fp"),
                [new NoNewOrphansSpec("leak_parent", "id", "leak_child", "parent_id")],
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                _fixture.StrictDisclosure),
            CancellationToken.None);

        PropertyResult result = Assert.Single(results);
        Assert.Equal(PropertyStatus.Fail, result.Status);
        Assert.Equal(SavErrorCode.OrphansFound, result.RedactedDetail);
        Assert.DoesNotContain(Canary, result.ToString(), StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("1", result.RedactedDetail!, StringComparison.Ordinal);
        Assert.DoesNotContain("2", result.RedactedDetail!, StringComparison.Ordinal);
    }

    [Fact]
    public void Schema_invariant_fail_never_leaks_digest_payload()
    {
        const string canaryDigest = "CANARY_DIGEST_do_not_egress";
        SchemaSnapshot before = new(
            "public",
            new Dictionary<string, long> { ["r"] = 1 },
            new Dictionary<string, string> { ["public.orders"] = "digest-v1" },
            new Dictionary<string, bool> { ["orders_pkey"] = true },
            relationKindByName: new Dictionary<string, string> { ["public.orders"] = "r" });
        SchemaSnapshot after = new(
            "public",
            new Dictionary<string, long> { ["r"] = 1 },
            new Dictionary<string, string> { ["public.orders"] = canaryDigest },
            new Dictionary<string, bool> { ["orders_pkey"] = true },
            relationKindByName: new Dictionary<string, string> { ["public.orders"] = "r" });

        PropertyResult result = SchemaInvariantProperty.Evaluate(
            before,
            after,
            new SchemaInvariantSpec([new SchemaInvariantRequirement("orders", "r")]));

        Assert.Equal(PropertyStatus.Fail, result.Status);
        Assert.Equal(SavErrorCode.SchemaInvariantFailed, result.RedactedDetail);
        Assert.DoesNotContain(canaryDigest, result.ToString(), StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("digest-v1", result.ToString(), StringComparison.OrdinalIgnoreCase);
    }
}
