using Sav.Application.Abstractions;
using Sav.Domain.Analysis;
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
public sealed class QueryEquivalentPropertyTests
{
    private readonly PostgresRoFixture _fixture;

    public QueryEquivalentPropertyTests(PostgresRoFixture fixture)
    {
        _fixture = fixture;
    }

    [Fact]
    public async Task Passes_when_both_except_all_diffs_are_zero()
    {
        await SeedAsync();
        PropertyResult result = await EvaluateAsync(
            "SELECT id, code FROM eq_items WHERE id <= 2 ORDER BY id",
            "SELECT id, code FROM eq_items WHERE code IN ('a', 'b') ORDER BY id");

        Assert.Equal(PropertyStatus.Pass, result.Status);
        Assert.Null(result.RedactedDetail);
    }

    [Fact]
    public async Task Fails_with_not_equivalent_when_multiplicities_differ()
    {
        await SeedAsync();
        await _fixture.ExecuteAdminAsync(
            "INSERT INTO public.eq_items(id, code) VALUES (4, 'a');");

        PropertyResult result = await EvaluateAsync(
            "SELECT code FROM eq_items WHERE code = 'a'",
            "SELECT code FROM eq_items WHERE id = 1");

        Assert.Equal(PropertyStatus.Fail, result.Status);
        Assert.Equal(SavErrorCode.NotEquivalent, result.RedactedDetail);
    }

    [Fact]
    public async Task Fails_when_only_left_contains_rows()
    {
        await SeedAsync();

        PropertyResult result = await EvaluateAsync(
            "SELECT id, code FROM eq_items WHERE id <= 2",
            "SELECT id, code FROM eq_items WHERE id = 1");

        Assert.Equal(PropertyStatus.Fail, result.Status);
        Assert.Equal(SavErrorCode.NotEquivalent, result.RedactedDetail);
    }

    [Fact]
    public async Task Fails_when_only_right_contains_rows()
    {
        await SeedAsync();

        PropertyResult result = await EvaluateAsync(
            "SELECT id, code FROM eq_items WHERE id = 1",
            "SELECT id, code FROM eq_items WHERE id <= 2");

        Assert.Equal(PropertyStatus.Fail, result.Status);
        Assert.Equal(SavErrorCode.NotEquivalent, result.RedactedDetail);
    }

    [Fact]
    public async Task Passes_when_both_sides_are_empty()
    {
        await SeedAsync();

        PropertyResult result = await EvaluateAsync(
            "SELECT id, code FROM eq_items WHERE id < 0",
            "SELECT id, code FROM eq_items WHERE id > 100");

        Assert.Equal(PropertyStatus.Pass, result.Status);
        Assert.Null(result.RedactedDetail);
    }

    private async Task SeedAsync()
    {
        await _fixture.ExecuteAdminAsync(
            """
            CREATE TABLE IF NOT EXISTS public.eq_items (
              id int PRIMARY KEY,
              code text NOT NULL
            );
            TRUNCATE public.eq_items;
            INSERT INTO public.eq_items(id, code) VALUES
              (1, 'a'),
              (2, 'b'),
              (3, 'c');
            GRANT SELECT ON public.eq_items TO sav_ro;
            """);
    }

    private async Task<PropertyResult> EvaluateAsync(string left, string right)
    {
        await using ReadOnlySessionFactory factory = _fixture.CreateFactory();
        await using IReadOnlySession session =
            await factory.OpenReadOnlySessionAsync(_fixture.Resolve(PostgresRoFixture.RoAlias), CancellationToken.None);

        PropertyOracle oracle = new(_fixture.Redactor);
        IReadOnlyList<PropertyResult> results = await oracle.EvaluateAsync(
            new PropertyEvaluationRequest(
                ExecutionEnvironment.RealReadOnlyAlias,
                new SqlIr(
                    "postgresql",
                    ["Select"],
                    ["eq_items"],
                    [],
                    ["id", "code"],
                    [],
                    [],
                    false,
                    false,
                    [],
                    [],
                    left,
                    "eq-fp"),
                [new QueryEquivalentSpec()],
                null,
                left,
                right,
                _fixture.Resolve(PostgresRoFixture.RoAlias),
                session,
                null,
                null,
                _fixture.StrictDisclosure,
                rightIr: new SqlIr(
                    "postgresql",
                    ["Select"],
                    ["eq_items"],
                    [],
                    ["id", "code"],
                    [],
                    [],
                    false,
                    false,
                    [],
                    [],
                    right,
                    "eq-fp-right")),
            CancellationToken.None);

        return Assert.Single(results);
    }
}
