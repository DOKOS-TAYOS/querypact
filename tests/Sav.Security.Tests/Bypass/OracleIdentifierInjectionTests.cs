using Sav.Domain.Errors;
using Sav.Infrastructure.Postgres.Oracle;

namespace Sav.Security.Tests.Bypass;

public sealed class OracleIdentifierInjectionTests
{
    [Theory]
    [InlineData("col); SELECT pg_read_file('pg_hba.conf')")]
    [InlineData("id; DROP TABLE users")]
    [InlineData("UserId")]
    [InlineData("\"UserId\"")]
    [InlineData("id\"")]
    [InlineData("")]
    [InlineData("a-b")]
    [InlineData("1abc")]
    public void Rejects_unsafe_or_mixed_case_identifiers(string identifier)
    {
        SavException ex = Assert.Throws<SavException>(
            () => PgIdentifierGuard.ValidateAndQuote(identifier, ["id", "payload"]));

        Assert.Equal(SavErrorCode.UnsafeIdentifier, ex.Code);
        Assert.Contains("unsafe_identifier", ex.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("pg_hba", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("DROP", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Accepts_safe_identifier_present_in_columns_read()
    {
        string quoted = PgIdentifierGuard.ValidateAndQuote("payload", ["id", "payload"]);
        Assert.Equal("\"payload\"", quoted);
    }

    [Fact]
    public void Rejects_safe_pattern_not_present_in_columns_read()
    {
        SavException ex = Assert.Throws<SavException>(
            () => PgIdentifierGuard.ValidateAndQuote("secret_col", ["id"]));
        Assert.Equal(SavErrorCode.UnsafeIdentifier, ex.Code);
    }

    [Fact]
    public void Quotes_by_doubling_internal_quotes_only_after_validation()
    {
        // Validated identifiers never contain quotes; quoting still uses delimited form.
        string quoted = PgIdentifierGuard.ValidateAndQuote("id", ["id"]);
        Assert.Equal("\"id\"", quoted);
        Assert.DoesNotContain("\"\"", quoted[1..^1], StringComparison.Ordinal);
    }
}
