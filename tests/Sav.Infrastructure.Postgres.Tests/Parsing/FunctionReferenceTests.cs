using Sav.Application.Abstractions;
using Sav.Infrastructure.Postgres.Parsing;

namespace Sav.Infrastructure.Postgres.Tests.Parsing;

public sealed class FunctionReferenceTests
{
    [Theory]
    [InlineData("SELECT SAV_SCOPE.SAV_SAFE_FN()", "sav_scope.sav_safe_fn", "sav_scope.sav_safe_fn")]
    [InlineData("SELECT \"sav_scope\".\"sav_safe_fn\"()", "sav_scope.sav_safe_fn", "sav_scope.sav_safe_fn")]
    [InlineData("SELECT sav_scope.\"SaV_Safe_Fn\"()", "sav_scope.SaV_Safe_Fn", "sav_scope.SaV_Safe_Fn")]
    [InlineData("SELECT \"SaV_Scope\".sav_safe_fn()", "SaV_Scope.sav_safe_fn", "SaV_Scope.sav_safe_fn")]
    [InlineData("SELECT PG_CATALOG.LOWER('x')", "lower", "pg_catalog.lower")]
    [InlineData("SELECT \"pg_catalog\".\"lower\"('x')", "lower", "pg_catalog.lower")]
    [InlineData("SELECT pg_catalog.\"LOWER\"('x')", "LOWER", "pg_catalog.LOWER")]
    [InlineData("SELECT \"PG_CATALOG\".lower('x')", "PG_CATALOG.lower", "PG_CATALOG.lower")]
    [InlineData("SELECT \" lower \"('x')", " lower ", " lower ")]
    [InlineData("SELECT \"*\"()", "*", "*")]
    [InlineData("SELECT \" \"()", " ", " ")]
    public void Function_identifiers_preserve_PostgreSql_normalization(string sql, string function, string reference)
    {
        SqlParseResult parsed = new LibPgQuerySqlParser().Parse(sql, CancellationToken.None);
        Assert.True(parsed.Success, parsed.RedactedMessage);
        Assert.Equal(function, Assert.Single(parsed.Ir!.Functions));
        Assert.Equal(reference, Assert.Single(parsed.Ir.FunctionReferences));
    }

    [Theory]
    [InlineData("SELECT sav_scope.sav_safe_fn(), sav_scope.\"SAV_SAFE_FN\"()", "sav_scope.SAV_SAFE_FN", "sav_scope.sav_safe_fn")]
    [InlineData("SELECT sav_scope.\"SAV_SAFE_FN\"(), sav_scope.sav_safe_fn()", "sav_scope.SAV_SAFE_FN", "sav_scope.sav_safe_fn")]
    [InlineData("SELECT sav_scope.sav_safe_fn(), \"SAV_SCOPE\".sav_safe_fn()", "SAV_SCOPE.sav_safe_fn", "sav_scope.sav_safe_fn")]
    [InlineData("SELECT lower('x'), \"LOWER\"('x')", "LOWER", "lower")]
    public void Case_distinct_function_references_survive_deduplication_in_ordinal_order(
        string sql, string first, string second)
    {
        SqlParseResult parsed = new LibPgQuerySqlParser().Parse(sql, CancellationToken.None);
        Assert.True(parsed.Success, parsed.RedactedMessage);
        Assert.Equal([first, second], parsed.Ir!.Functions);
        Assert.Equal([first, second], parsed.Ir.FunctionReferences);
    }

    [Fact]
    public void Equivalent_normalized_functions_deduplicate_but_keep_lexical_qualification()
    {
        SqlParseResult parsed = new LibPgQuerySqlParser().Parse(
            "SELECT lower('x'), LOWER('x'), \"lower\"('x'), pg_catalog.lower('x')", CancellationToken.None);
        Assert.True(parsed.Success, parsed.RedactedMessage);
        Assert.Equal(["lower"], parsed.Ir!.Functions);
        Assert.Equal(["lower", "pg_catalog.lower"], parsed.Ir.FunctionReferences);
    }

    [Theory]
    [InlineData("SELECT \"sav_scope.sav_safe_fn\"()")]
    [InlineData("SELECT \"pg_catalog.lower\"('x')")]
    [InlineData("SELECT \"sav.scope\".sav_safe_fn()")]
    public void Delimited_function_components_with_dots_fail_closed(string sql)
    {
        SqlParseResult parsed = new LibPgQuerySqlParser().Parse(sql, CancellationToken.None);
        Assert.True(parsed.Success, parsed.RedactedMessage);
        Assert.Contains("unsupported_construct", parsed.Ir!.RiskCodes);
    }

    [Fact]
    public void Keeps_lexical_function_reference()
    {
        SqlParseResult result = new LibPgQuerySqlParser().Parse(
            "SELECT pg_catalog.length('x')",
            CancellationToken.None);

        Assert.True(result.Success, result.RedactedMessage);
        Assert.Contains("length", result.Ir!.Functions, StringComparer.OrdinalIgnoreCase);
        Assert.Contains("pg_catalog.length", result.Ir.FunctionReferences, StringComparer.Ordinal);

        SqlParseResult unqualified = new LibPgQuerySqlParser().Parse(
            "SELECT length('x')",
            CancellationToken.None);
        Assert.True(unqualified.Success, unqualified.RedactedMessage);
        Assert.Contains("length", unqualified.Ir!.FunctionReferences, StringComparer.Ordinal);
    }
}
