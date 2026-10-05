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
public sealed class AffectedRowsPropertyTests
{
    private readonly PostgresRoFixture _fixture;

    public AffectedRowsPropertyTests(PostgresRoFixture fixture)
    {
        _fixture = fixture;
    }

    [Fact]
    public async Task Passes_when_records_affected_within_inclusive_range()
    {
        await SeedAsync();
        PropertyResult result = await EvaluateAsync(
            "INSERT INTO public.aff_rows_items(id, label) VALUES (3, 'c')",
            new AffectedRowsSpec(1, 1));

        Assert.Equal(PropertyStatus.Pass, result.Status);
        Assert.Null(result.RedactedDetail);
    }

    [Fact]
    public async Task Fails_with_affected_rows_out_of_range()
    {
        await SeedAsync();
        PropertyResult result = await EvaluateAsync(
            "UPDATE public.aff_rows_items SET label = 'x' WHERE id = 999",
            new AffectedRowsSpec(1, 5));

        Assert.Equal(PropertyStatus.Fail, result.Status);
        Assert.Equal(SavErrorCode.AffectedRowsOutOfRange, result.RedactedDetail);
    }

    [Fact]
    public async Task Open_max_inclusive_null_accepts_any_count_at_or_above_min()
    {
        await SeedAsync();
        PropertyResult result = await EvaluateAsync(
            "DELETE FROM public.aff_rows_items WHERE id IN (1, 2)",
            new AffectedRowsSpec(2, null));

        Assert.Equal(PropertyStatus.Pass, result.Status);
    }

    private async Task SeedAsync()
    {
        await _fixture.ExecuteAdminAsync(
            """
            CREATE TABLE IF NOT EXISTS public.aff_rows_items (
              id int PRIMARY KEY,
              label text NOT NULL
            );
            TRUNCATE public.aff_rows_items;
            INSERT INTO public.aff_rows_items(id, label) VALUES
              (1, 'a'),
              (2, 'b');
            """);
    }

    private async Task<PropertyResult> EvaluateAsync(string dml, AffectedRowsSpec spec)
    {
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
                    ["Insert"],
                    [],
                    ["aff_rows_items"],
                    [],
                    ["label"],
                    [],
                    false,
                    false,
                    [],
                    [],
                    dml,
                    "aff-fp"),
                [spec],
                dml,
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
}
