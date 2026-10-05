using Sav.Domain.Errors;
using Sav.Infrastructure.Postgres.Oracle;

namespace Sav.Security.Tests.Bypass;

public sealed class UniqueNonNullIdentifierBypassTests
{
    [Theory]
    [InlineData("col); SELECT pg_read_file('pg_hba.conf')")]
    [InlineData("code; DROP TABLE users")]
    [InlineData("UserId")]
    [InlineData("\"code\"")]
    public void Unique_template_rejects_unsafe_column_identifiers(string column)
    {
        SavException ex = Assert.Throws<SavException>(
            () => OracleSqlBoundary.BuildWrappedCommand(
                OracleSqlTemplateKind.UniqueDistinctCount,
                OracleTestIr.Create(columnsRead: ["code"], agentSql: "SELECT code FROM t"),
                "SELECT code FROM t",
                policyAllowedFunctions: [],
                propertyColumn: column));

        Assert.Equal(SavErrorCode.UnsafeIdentifier, ex.Code);
        Assert.DoesNotContain("pg_hba", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Unique_template_quotes_safe_column()
    {
        string wrapped = OracleSqlBoundary.BuildWrappedCommand(
            OracleSqlTemplateKind.UniqueDistinctCount,
            OracleTestIr.Create(columnsRead: ["code"], agentSql: "SELECT code FROM t"),
            "SELECT code FROM t",
            policyAllowedFunctions: [],
            propertyColumn: "code");

        Assert.Contains("COUNT(\"code\")", wrapped, StringComparison.Ordinal);
        Assert.Contains("COUNT(DISTINCT \"code\")", wrapped, StringComparison.Ordinal);
        Assert.StartsWith("SELECT COUNT(*)::bigint AS v FROM (", wrapped, StringComparison.Ordinal);
    }

    [Fact]
    public void Non_null_template_quotes_safe_column()
    {
        string wrapped = OracleSqlBoundary.BuildWrappedCommand(
            OracleSqlTemplateKind.NonNullIsNullCount,
            OracleTestIr.Create(columnsRead: ["note"], agentSql: "SELECT note FROM t"),
            "SELECT note FROM t",
            policyAllowedFunctions: [],
            propertyColumn: "note");

        Assert.Contains("WHERE \"note\" IS NULL", wrapped, StringComparison.Ordinal);
    }
}
