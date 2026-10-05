using Sav.Application.Abstractions;
using Sav.Domain.Contracts;
using Sav.Domain.Decisions;
using Sav.Domain.Errors;
using Sav.Domain.Execution;
using Sav.Domain.Properties;
using Sav.Infrastructure.Postgres.Oracle;
using Sav.Infrastructure.Postgres.Targets;
using Sav.Infrastructure.Postgres.Tests.Fixtures;

namespace Sav.Infrastructure.Postgres.Tests.Oracle;

[Collection(nameof(PostgresRoCollection))]
public sealed class UniqueNonNullPropertyTests
{
    private readonly PostgresRoFixture _fixture;

    public UniqueNonNullPropertyTests(PostgresRoFixture fixture)
    {
        _fixture = fixture;
    }

    [Fact]
    public async Task Unique_passes_when_all_values_distinct()
    {
        await SeedAsync();
        PropertyResult result = await EvaluateAsync(
            "SELECT code FROM uniq_nn_items",
            new UniqueSpec("code"),
            ["code"]);

        Assert.Equal(PropertyStatus.Pass, result.Status);
        Assert.Null(result.RedactedDetail);
    }

    [Fact]
    public async Task Unique_passes_when_result_is_empty()
    {
        await SeedAsync();
        PropertyResult result = await EvaluateAsync(
            "SELECT code FROM uniq_nn_items WHERE false",
            new UniqueSpec("code"),
            ["code"]);

        Assert.Equal(PropertyStatus.Pass, result.Status);
        Assert.Null(result.RedactedDetail);
    }

    [Fact]
    public async Task Unique_passes_when_all_values_are_null()
    {
        await SeedAsync();
        await _fixture.ExecuteAdminAsync(
            "UPDATE public.uniq_nn_items SET code = NULL;");

        PropertyResult result = await EvaluateAsync(
            "SELECT code FROM uniq_nn_items",
            new UniqueSpec("code"),
            ["code"]);

        Assert.Equal(PropertyStatus.Pass, result.Status);
        Assert.Null(result.RedactedDetail);
    }

    [Fact]
    public async Task Unique_passes_with_single_null()
    {
        await SeedAsync();
        await _fixture.ExecuteAdminAsync(
            "INSERT INTO public.uniq_nn_items(id, code, note) VALUES (3, NULL, NULL);");

        PropertyResult result = await EvaluateAsync(
            "SELECT code FROM uniq_nn_items",
            new UniqueSpec("code"),
            ["code"]);

        Assert.Equal(PropertyStatus.Pass, result.Status);
        Assert.Null(result.RedactedDetail);
    }

    [Fact]
    public async Task Unique_passes_with_multiple_nulls()
    {
        await SeedAsync();
        await _fixture.ExecuteAdminAsync(
            """
            INSERT INTO public.uniq_nn_items(id, code, note) VALUES
              (3, NULL, NULL),
              (4, NULL, 'z');
            """);

        PropertyResult result = await EvaluateAsync(
            "SELECT code FROM uniq_nn_items",
            new UniqueSpec("code"),
            ["code"]);

        Assert.Equal(PropertyStatus.Pass, result.Status);
        Assert.Null(result.RedactedDetail);
    }

    [Fact]
    public async Task Unique_and_non_null_are_independent_for_nulls()
    {
        await SeedAsync();
        await _fixture.ExecuteAdminAsync(
            """
            INSERT INTO public.uniq_nn_items(id, code, note) VALUES
              (3, NULL, NULL),
              (4, NULL, 'z');
            """);

        PropertyResult unique = await EvaluateAsync(
            "SELECT code FROM uniq_nn_items",
            new UniqueSpec("code"),
            ["code"]);
        PropertyResult nonNull = await EvaluateAsync(
            "SELECT code FROM uniq_nn_items",
            new NonNullSpec("code"),
            ["code"]);

        Assert.Equal(PropertyStatus.Pass, unique.Status);
        Assert.Null(unique.RedactedDetail);
        Assert.Equal(PropertyStatus.Fail, nonNull.Status);
        Assert.Equal(SavErrorCode.NullFound, nonNull.RedactedDetail);
    }

    [Fact]
    public async Task Unique_fails_with_unique_violation_on_duplicates()
    {
        await SeedAsync();
        await _fixture.ExecuteAdminAsync(
            """
            INSERT INTO public.uniq_nn_items(id, code, note) VALUES
              (3, 'a', NULL),
              (4, NULL, NULL);
            """);

        PropertyResult result = await EvaluateAsync(
            "SELECT code FROM uniq_nn_items",
            new UniqueSpec("code"),
            ["code"]);

        Assert.Equal(PropertyStatus.Fail, result.Status);
        Assert.Equal(SavErrorCode.UniqueViolation, result.RedactedDetail);
        Assert.DoesNotContain("2", result.RedactedDetail!, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Non_null_passes_when_no_nulls()
    {
        await SeedAsync();
        PropertyResult result = await EvaluateAsync(
            "SELECT code FROM uniq_nn_items WHERE code IS NOT NULL",
            new NonNullSpec("code"),
            ["code"]);

        Assert.Equal(PropertyStatus.Pass, result.Status);
        Assert.Null(result.RedactedDetail);
    }

    [Fact]
    public async Task Non_null_fails_with_null_found()
    {
        await SeedAsync();
        PropertyResult result = await EvaluateAsync(
            "SELECT note FROM uniq_nn_items",
            new NonNullSpec("note"),
            ["note"]);

        Assert.Equal(PropertyStatus.Fail, result.Status);
        Assert.Equal(SavErrorCode.NullFound, result.RedactedDetail);
        Assert.DoesNotContain("1", result.RedactedDetail!, StringComparison.Ordinal);
    }

    private async Task SeedAsync()
    {
        await _fixture.ExecuteAdminAsync(
            """
            CREATE TABLE IF NOT EXISTS public.uniq_nn_items (
              id int PRIMARY KEY,
              code text NULL,
              note text NULL
            );
            TRUNCATE public.uniq_nn_items;
            INSERT INTO public.uniq_nn_items(id, code, note) VALUES
              (1, 'a', 'x'),
              (2, 'b', NULL);
            GRANT SELECT ON public.uniq_nn_items TO sav_ro;
            """);
    }

    private async Task<PropertyResult> EvaluateAsync(
        string agent,
        PropertySpec spec,
        string[] columnsRead)
    {
        await using ReadOnlySessionFactory factory = _fixture.CreateFactory();
        await using IReadOnlySession session =
            await factory.OpenReadOnlySessionAsync(_fixture.Resolve(PostgresRoFixture.RoAlias), CancellationToken.None);

        PropertyOracle oracle = new(_fixture.Redactor);
        IReadOnlyList<PropertyResult> results = await oracle.EvaluateAsync(
            new PropertyEvaluationRequest(
                ExecutionEnvironment.RealReadOnlyAlias,
                new Sav.Domain.Analysis.SqlIr(
                    "postgresql",
                    ["Select"],
                    ["uniq_nn_items"],
                    [],
                    columnsRead,
                    [],
                    [],
                    false,
                    false,
                    [],
                    [],
                    agent,
                    "uniq-nn-fp"),
                [spec],
                agent,
                null,
                null,
                _fixture.Resolve(PostgresRoFixture.RoAlias),
                session,
                null,
                null,
                _fixture.StrictDisclosure),
            CancellationToken.None);

        return Assert.Single(results);
    }
}
