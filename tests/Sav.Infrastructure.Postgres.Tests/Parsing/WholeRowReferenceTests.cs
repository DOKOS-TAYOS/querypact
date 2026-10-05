using Sav.Application.Abstractions;
using Sav.Infrastructure.Postgres.Parsing;

namespace Sav.Infrastructure.Postgres.Tests.Parsing;

public sealed class WholeRowReferenceTests
{
    private readonly ISqlParser _parser = new LibPgQuerySqlParser();

    [Theory]
    [InlineData("SELECT u FROM users AS u")]
    [InlineData("SELECT users FROM users")]
    [InlineData("SELECT u FROM public.users AS u")]
    [InlineData("SELECT ROW(u) FROM users u")]
    [InlineData("SELECT (u).ssn FROM users u")]
    [InlineData("SELECT q FROM (SELECT id FROM users) AS q")]
    [InlineData("WITH q AS (SELECT id FROM users) SELECT q FROM q")]
    [InlineData("SELECT (SELECT u FROM logs AS l) FROM users AS u")]
    [InlineData("SELECT j FROM users u JOIN accounts a USING (ssn) AS j")]
    [InlineData("SELECT u FROM users u JOIN accounts a USING (ssn) AS j")]
    [InlineData("SELECT 1 FROM users u, LATERAL (SELECT u) AS q")]
    [InlineData("SELECT u.id FROM users u NATURAL JOIN accounts a")]
    public void Potential_whole_row_references_fail_closed(string sql)
    {
        SqlParseResult parsed = _parser.Parse(sql, CancellationToken.None);
        Assert.True(parsed.Success, parsed.RedactedMessage);
        Assert.Contains("unsupported_construct", parsed.Ir!.RiskCodes);
    }

    [Fact]
    public void Join_using_keys_are_recorded_as_read_columns()
    {
        SqlParseResult parsed = _parser.Parse(
            "SELECT u.id FROM users u JOIN accounts a USING (ssn) AS j",
            CancellationToken.None);
        Assert.True(parsed.Success, parsed.RedactedMessage);
        Assert.Contains("ssn", parsed.Ir!.ColumnsRead, StringComparer.OrdinalIgnoreCase);
        Assert.DoesNotContain("unsupported_construct", parsed.Ir.RiskCodes);
    }

    [Theory]
    [InlineData("SELECT u.email FROM users AS u")]
    [InlineData("SELECT email FROM users AS u")]
    [InlineData("SELECT u.id FROM public.users AS u")]
    [InlineData("WITH q AS (SELECT email FROM users) SELECT email FROM q")]
    [InlineData("SELECT u.id FROM users AS u WHERE u.email IS NOT NULL")]
    [InlineData("WITH q AS (SELECT u FROM logs) SELECT 1 FROM users AS u")]
    [InlineData("SELECT 1 FROM users AS u, (SELECT u FROM logs) AS q")]
    public void Individual_column_references_remain_supported(string sql)
    {
        SqlParseResult parsed = _parser.Parse(sql, CancellationToken.None);
        Assert.True(parsed.Success, parsed.RedactedMessage);
        Assert.DoesNotContain("unsupported_construct", parsed.Ir!.RiskCodes);
    }
}
