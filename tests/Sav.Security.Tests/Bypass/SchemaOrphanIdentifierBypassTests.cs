using Sav.Domain.Errors;
using Sav.Infrastructure.Postgres.Oracle;

namespace Sav.Security.Tests.Bypass;

public sealed class SchemaOrphanIdentifierBypassTests
{
    [Theory]
    [InlineData("orders); SELECT pg_read_file('pg_hba.conf')")]
    [InlineData("UserId")]
    [InlineData("\"orders\"")]
    [InlineData("orders; DROP TABLE t")]
    public void No_new_orphans_rejects_unsafe_parent_table(string parentTable)
    {
        SavException ex = Assert.Throws<SavException>(
            () => OracleSqlBoundary.BuildNoNewOrphansCommand(
                parentTable,
                "id",
                "order_items",
                "order_id"));

        Assert.Equal(SavErrorCode.UnsafeIdentifier, ex.Code);
        Assert.DoesNotContain("pg_hba", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("id); SELECT 1")]
    [InlineData("OrderId")]
    public void No_new_orphans_rejects_unsafe_keys(string key)
    {
        SavException ex = Assert.Throws<SavException>(
            () => OracleSqlBoundary.BuildNoNewOrphansCommand(
                "orders",
                key,
                "order_items",
                "order_id"));

        Assert.Equal(SavErrorCode.UnsafeIdentifier, ex.Code);
    }

    [Fact]
    public void No_new_orphans_quotes_safe_identifiers_in_count_template()
    {
        string sql = OracleSqlBoundary.BuildNoNewOrphansCommand(
            "orders",
            "id",
            "order_items",
            "order_id");

        Assert.Equal(
            "SELECT COUNT(*)::bigint AS v FROM \"order_items\" c WHERE c.\"order_id\" IS DISTINCT FROM NULL AND NOT EXISTS ( SELECT 1 FROM \"orders\" p WHERE p.\"id\" = c.\"order_id\" )",
            sql);
        Assert.DoesNotContain("SELECT *", sql, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("orders); DROP TABLE t")]
    [InlineData("Orders")]
    public void Schema_invariant_rejects_unsafe_relation_name(string relationName)
    {
        PropertyResultViaInvariant(relationName, "r", out string? code);
        Assert.Equal(SavErrorCode.UnsafeIdentifier, code);
    }

    private static void PropertyResultViaInvariant(string relationName, string relkind, out string? code)
    {
        Sav.Domain.Schema.SchemaSnapshot snap = new(
            "public",
            new Dictionary<string, long> { ["r"] = 1 },
            new Dictionary<string, string> { ["public.orders"] = "d1" },
            new Dictionary<string, bool>());

        Sav.Domain.Properties.PropertyResult result =
            Sav.Infrastructure.Postgres.Oracle.Properties.SchemaInvariantProperty.Evaluate(
                snap,
                snap,
                new Sav.Domain.Contracts.SchemaInvariantSpec(
                [
                    new Sav.Domain.Contracts.SchemaInvariantRequirement(relationName, relkind),
                ]));

        code = result.RedactedDetail;
        Assert.Equal(Sav.Domain.Decisions.PropertyStatus.Error, result.Status);
    }
}
