using Sav.Infrastructure.Postgres.Catalog;

namespace Sav.Infrastructure.Postgres.Tests.Catalog;

public sealed class PgCatalogObjectNameTests
{
    [Theory]
    [InlineData("orders", null, "orders")]
    [InlineData(" public.orders ", "public", "orders")]
    [InlineData("Orders", null, "Orders")]
    [InlineData("_schema._table", "_schema", "_table")]
    public void TryParse_accepts_safe_object_names(
        string input,
        string? expectedSchema,
        string expectedRelation)
    {
        bool parsed = PgCatalogObjectName.TryParse(input, out string? schema, out string relation);

        Assert.True(parsed);
        Assert.Equal(expectedSchema, schema);
        Assert.Equal(expectedRelation, relation);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("public.")]
    [InlineData(".orders")]
    [InlineData("public.orders.extra")]
    [InlineData("public-order")]
    [InlineData("\"public\".orders")]
    public void TryParse_rejects_unsafe_object_names(string? input)
    {
        bool parsed = PgCatalogObjectName.TryParse(input!, out _, out _);

        Assert.False(parsed);
    }

    [Theory]
    [InlineData("orders", "\"orders\"")]
    [InlineData("MixedCase", "\"MixedCase\"")]
    [InlineData("a\"b", "\"a\"\"b\"")]
    public void QuoteIdentifier_preserves_case_and_escapes_quotes(string input, string expected)
    {
        Assert.Equal(expected, PgCatalogObjectName.QuoteIdentifier(input));
    }

    [Fact]
    public void EscapeLiteral_doubles_single_quotes()
    {
        Assert.Equal("a''b", PgCatalogObjectName.EscapeLiteral("a'b"));
    }
}
