using Sav.Application.Abstractions;
using Sav.Domain.Analysis;
using Sav.Domain.Contracts;
using Sav.Domain.Decisions;
using Sav.Domain.Errors;
using Sav.Domain.Execution;
using Sav.Domain.Properties;
using Sav.Infrastructure.Postgres.Oracle;
using Sav.Infrastructure.Postgres.Tests.Fixtures;

namespace Sav.Infrastructure.Postgres.Tests.Oracle;

[Collection(nameof(PostgresRoCollection))]
public sealed class NoNewOrphansPropertyTests
{
    private readonly PostgresRoFixture _fixture;

    public NoNewOrphansPropertyTests(PostgresRoFixture fixture)
    {
        _fixture = fixture;
    }

    [Fact]
    public async Task Passes_when_every_child_key_has_parent()
    {
        await SeedAsync(includeOrphan: false, includeNullChild: false);
        PropertyResult result = await EvaluateAsync();

        Assert.Equal(PropertyStatus.Pass, result.Status);
        Assert.Null(result.RedactedDetail);
    }

    [Fact]
    public async Task Ignores_null_child_keys()
    {
        await SeedAsync(includeOrphan: false, includeNullChild: true);
        PropertyResult result = await EvaluateAsync();

        Assert.Equal(PropertyStatus.Pass, result.Status);
        Assert.Null(result.RedactedDetail);
    }

    [Fact]
    public async Task Partially_null_composite_child_key_is_still_checked_for_parent()
    {
        await _fixture.ExecuteAdminAsync(
            """
            DROP TABLE IF EXISTS public.orphan_composite_child;
            DROP TABLE IF EXISTS public.orphan_composite_parent;
            DROP TYPE IF EXISTS public.orphan_composite_key CASCADE;
            CREATE TYPE public.orphan_composite_key AS (
              tenant_id int,
              local_id int
            );
            CREATE TABLE public.orphan_composite_parent (
              id public.orphan_composite_key
            );
            CREATE TABLE public.orphan_composite_child (
              id int PRIMARY KEY,
              parent_id public.orphan_composite_key
            );
            INSERT INTO public.orphan_composite_child(id, parent_id)
            VALUES (1, ROW(999, NULL)::public.orphan_composite_key);
            """);

        try
        {
            PropertyResult result = await EvaluateAsync(
                new NoNewOrphansSpec(
                    "orphan_composite_parent",
                    "id",
                    "orphan_composite_child",
                    "parent_id"));

            Assert.Equal(PropertyStatus.Fail, result.Status);
            Assert.Equal(SavErrorCode.OrphansFound, result.RedactedDetail);
        }
        finally
        {
            await _fixture.ExecuteAdminAsync(
                """
                DROP TABLE IF EXISTS public.orphan_composite_child;
                DROP TABLE IF EXISTS public.orphan_composite_parent;
                DROP TYPE IF EXISTS public.orphan_composite_key CASCADE;
                """);
        }
    }

    [Fact]
    public async Task Fails_with_orphans_found_when_child_lacks_parent()
    {
        await SeedAsync(includeOrphan: true, includeNullChild: false);
        PropertyResult result = await EvaluateAsync();

        Assert.Equal(PropertyStatus.Fail, result.Status);
        Assert.Equal(SavErrorCode.OrphansFound, result.RedactedDetail);
        Assert.DoesNotContain("999", result.RedactedDetail!, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Real_alias_returns_property_environment_forbidden()
    {
        PropertyOracle oracle = new(_fixture.Redactor);
        IReadOnlyList<PropertyResult> results = await oracle.EvaluateAsync(
            new PropertyEvaluationRequest(
                ExecutionEnvironment.RealReadOnlyAlias,
                DummyIr(),
                [new NoNewOrphansSpec("orphan_parent", "id", "orphan_child", "parent_id")],
                null,
                null,
                null,
                _fixture.Resolve(PostgresRoFixture.RoAlias),
                null,
                null,
                null,
                _fixture.StrictDisclosure),
            CancellationToken.None);

        PropertyResult result = Assert.Single(results);
        Assert.Equal(PropertyStatus.Error, result.Status);
        Assert.Equal(SavErrorCode.PropertyEnvironmentForbidden, result.RedactedDetail);
    }

    private async Task SeedAsync(bool includeOrphan, bool includeNullChild)
    {
        string orphanInsert = includeOrphan
            ? "INSERT INTO public.orphan_child(id, parent_id) VALUES (3, 999);"
            : string.Empty;
        string nullInsert = includeNullChild
            ? "INSERT INTO public.orphan_child(id, parent_id) VALUES (4, NULL);"
            : string.Empty;

        await _fixture.ExecuteAdminAsync(
            $"""
            CREATE TABLE IF NOT EXISTS public.orphan_parent (
              id int PRIMARY KEY
            );
            CREATE TABLE IF NOT EXISTS public.orphan_child (
              id int PRIMARY KEY,
              parent_id int
            );
            ALTER TABLE public.orphan_child ALTER COLUMN parent_id DROP NOT NULL;
            TRUNCATE public.orphan_child, public.orphan_parent;
            INSERT INTO public.orphan_parent(id) VALUES (1), (2);
            INSERT INTO public.orphan_child(id, parent_id) VALUES (1, 1), (2, 2);
            {orphanInsert}
            {nullInsert}
            """);
    }

    private async Task<PropertyResult> EvaluateAsync(NoNewOrphansSpec? spec = null)
    {
        EphemeralSessionFactory ephemeralFactory = new(_fixture.Redactor, _fixture.StrictDisclosure);
        PropertyOracle oracle = new(
            _fixture.Redactor,
            ephemeralSessionFactory: ephemeralFactory,
            ephemeralConnectionString: _fixture.AdminConnectionString);

        IReadOnlyList<PropertyResult> results = await oracle.EvaluateAsync(
            new PropertyEvaluationRequest(
                ExecutionEnvironment.EphemeralContainer,
                DummyIr(),
                [spec ?? new NoNewOrphansSpec("orphan_parent", "id", "orphan_child", "parent_id")],
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                _fixture.StrictDisclosure),
            CancellationToken.None);

        return Assert.Single(results);
    }

    private static SqlIr DummyIr()
    {
        return new SqlIr(
            "postgresql",
            ["Select"],
            ["orphan_parent", "orphan_child"],
            [],
            ["id", "parent_id"],
            [],
            [],
            false,
            false,
            [],
            [],
            "SELECT 1",
            "orphan-fp");
    }
}
