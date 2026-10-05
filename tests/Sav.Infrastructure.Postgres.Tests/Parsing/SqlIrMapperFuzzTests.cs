using Sav.Application.Abstractions;
using Sav.Infrastructure.Postgres.Parsing;

namespace Sav.Infrastructure.Postgres.Tests.Parsing;

public sealed class SqlIrMapperFuzzTests
{
    private readonly ISqlParser _parser = new LibPgQuerySqlParser();

    [Theory]
    [InlineData("SELECT id FROM users")]
    [InlineData("select   id   from   users")]
    [InlineData("SELECT id FROM users /* comment */")]
    [InlineData("SELECT id FROM users;")]
    public void Whitespace_case_and_comment_variants_remain_parsable(string sql)
    {
        SqlParseResult result = _parser.Parse(sql, CancellationToken.None);
        Assert.True(result.Success, result.RedactedMessage);
        Assert.Contains("users", result.Ir!.TablesRead);
    }

    [Fact]
    public void Adversarial_multi_statement_subset_is_flagged()
    {
        SqlParseResult result = _parser.Parse("SELECT 1; SELECT 2; SELECT 3", CancellationToken.None);
        Assert.True(result.Success);
        Assert.True(result.Ir!.HasMultipleStatements);
    }
}
