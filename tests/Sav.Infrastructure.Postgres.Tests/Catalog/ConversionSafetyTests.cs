using Sav.Application.Abstractions;
using Sav.Domain.Analysis;
using Sav.Domain.Targets;
using Sav.Infrastructure.Postgres.Catalog;
using Sav.Infrastructure.Postgres.Parsing;

namespace Sav.Infrastructure.Postgres.Tests.Catalog;

public sealed class ConversionSafetyTests
{
    private static readonly TargetAlias Alias = new("test", "fingerprint");

    [Theory]
    [InlineData("SELECT \" lower \"('x')")]
    [InlineData("SELECT pg_catalog.\"lower \"('x')")]
    [InlineData("SELECT \" pg_catalog\".lower('x')")]
    public async Task Catalog_function_identifiers_cannot_be_trimmed_into_different_names(string sql)
    {
        MetadataSession session = new([new OracleScalarRow(true, null, null)]);
        Assert.False(await PgConversionSafety.IsSafeAsync([Parse(sql)], session, CancellationToken.None));
        Assert.Empty(session.Sql);
    }

    [Theory]
    [InlineData("SELECT sav_scope.sav_safe_fn(), sav_scope.\"SAV_SAFE_FN\"()", "sav_scope", "sav_safe_fn", "sav_scope", "SAV_SAFE_FN")]
    [InlineData("SELECT sav_scope.sav_safe_fn(), \"SAV_SCOPE\".sav_safe_fn()", "sav_scope", "sav_safe_fn", "SAV_SCOPE", "sav_safe_fn")]
    [InlineData("SELECT pg_catalog.lower('x'), pg_catalog.\"LOWER\"('x')", "pg_catalog", "lower", "pg_catalog", "LOWER")]
    public async Task Catalog_metadata_keeps_case_distinct_functions_in_single_and_pair_validation(
        string sql, string schema1, string name1, string schema2, string name2)
    {
        SqlAnalysis analysis = Parse(sql);
        MetadataSession session = new([new OracleScalarRow(true, null, null)]);
        PgCatalogResolver resolver = new();
        SqlAnalysis single = await resolver.EnrichAsync(analysis, Alias, session, CancellationToken.None);
        (SqlAnalysis left, SqlAnalysis right) = await resolver.EnrichPairAsync(
            analysis, single, Alias, session, CancellationToken.None);

        Assert.Empty(single.Ir.RiskCodes);
        Assert.Empty(left.Ir.RiskCodes);
        Assert.Empty(right.Ir.RiskCodes);
        Assert.Equal(2, single.Ir.Functions.Count);
        Assert.Equal(analysis.Ir.Functions, single.Ir.Functions);
        Assert.Equal(analysis.Ir.FunctionReferences, single.Ir.FunctionReferences);
        Assert.Equal(analysis.Ir.Functions, left.Ir.Functions);
        Assert.Equal(analysis.Ir.FunctionReferences, right.Ir.FunctionReferences);
        Assert.Equal(2, session.Sql.Count);
        Assert.All(session.Sql, metadata =>
        {
            string first = $"('function'::pg_catalog.text, '{schema1}'::pg_catalog.name, '{name1}'::pg_catalog.name, false)";
            string second = $"('function'::pg_catalog.text, '{schema2}'::pg_catalog.name, '{name2}'::pg_catalog.name, false)";
            Assert.Equal(1, metadata.Split(first, StringSplitOptions.None).Length - 1);
            Assert.Equal(1, metadata.Split(second, StringSplitOptions.None).Length - 1);
            Assert.DoesNotContain(sql, metadata);
        });
    }

    [Theory]
    [InlineData("SELECT 1")]
    [InlineData("SELECT -7")]
    [InlineData("SELECT 0 AS first, 2147483647 AS last")]
    [InlineData("SELECT (7) AS value /* harmless */")]
    public async Task Proven_int4_constants_keep_type_metadata_but_do_not_check_cast_paths(string sql)
    {
        SqlAnalysis analysis = Parse(sql);
        Assert.True(analysis.Ir.Int4ConstantProjectionCount > 0, PgSqlParser.Parser.Parse(sql).Value?.ToString());
        MetadataSession session = new([new OracleScalarRow(true, null, null)]);
        PgCatalogResolver resolver = new();
        SqlAnalysis single = await resolver.EnrichAsync(analysis, Alias, session, CancellationToken.None);
        Assert.Empty(single.Ir.RiskCodes);
        Assert.Equal(analysis.Ir.Int4ConstantProjectionCount, single.Ir.Int4ConstantProjectionCount);
        (SqlAnalysis left, SqlAnalysis right) = await resolver.EnrichPairAsync(
            single, analysis, Alias, session, CancellationToken.None);
        Assert.Empty(left.Ir.RiskCodes);
        Assert.Empty(right.Ir.RiskCodes);
        Assert.Equal(2, session.Sql.Count);
        Assert.All(session.Sql, metadata =>
        {
            Assert.DoesNotContain("pg_catalog.pg_cast", metadata);
            Assert.DoesNotContain("pg_catalog.pg_attribute", metadata);
            Assert.Contains("'int4'::pg_catalog.name", metadata);
            Assert.Contains("t.typinput", metadata);
            Assert.StartsWith("WITH requested(", metadata);
            Assert.DoesNotContain("EXPLAIN", metadata);
        });
    }

    [Theory]
    [InlineData(0, true)]
    [InlineData(1, null)]
    [InlineData(1, false)]
    [InlineData(2, true)]
    public async Task Proven_constants_still_reject_inconclusive_type_metadata(int count, bool? safe)
    {
        MetadataSession session = new(Enumerable.Repeat(new OracleScalarRow(safe, null, null), count).ToArray());
        PgCatalogResolver resolver = new();
        Assert.Contains("unsupported_construct", (await resolver.EnrichAsync(
            Parse("SELECT 1"), Alias, session, CancellationToken.None)).Ir.RiskCodes);
        (SqlAnalysis left, SqlAnalysis right) = await resolver.EnrichPairAsync(
            Parse("SELECT 1"), Parse("SELECT 2"), Alias, session, CancellationToken.None);
        Assert.Contains("unsupported_construct", left.Ir.RiskCodes);
        Assert.Contains("unsupported_construct", right.Ir.RiskCodes);
    }

    [Theory]
    [InlineData("SELECT 1.0")]
    [InlineData("SELECT 2147483648")]
    [InlineData("SELECT 'ok'")]
    [InlineData("SELECT NULL")]
    [InlineData("SELECT true")]
    [InlineData("SELECT 1::integer")]
    [InlineData("SELECT CASE WHEN true THEN 1 ELSE 2.0 END")]
    [InlineData("SELECT 1 UNION ALL SELECT 2.0")]
    [InlineData("SELECT ARRAY[1,2]")]
    [InlineData("SELECT 1 WHERE true")]
    [InlineData("SELECT 1 LIMIT 1")]
    [InlineData("SELECT 1 ORDER BY 1")]
    [InlineData("SELECT DISTINCT 1")]
    [InlineData("SELECT (SELECT 1)")]
    [InlineData("WITH q AS (SELECT 1) SELECT 1")]
    [InlineData("SELECT 1; SELECT 2")]
    public async Task Unproven_constant_shapes_keep_global_cast_check(string sql)
    {
        SqlAnalysis analysis = Parse(sql);
        Assert.Equal(0, analysis.Ir.Int4ConstantProjectionCount);
        MetadataSession session = new([new OracleScalarRow(false, null, null)]);
        Assert.False(await PgConversionSafety.IsSafeAsync([analysis], session, CancellationToken.None));
        Assert.Contains("pg_catalog.pg_cast", Assert.Single(session.Sql));
    }

    [Fact]
    public async Task Pair_with_different_projection_counts_keeps_global_cast_check()
    {
        MetadataSession session = new([new OracleScalarRow(false, null, null)]);
        (SqlAnalysis left, SqlAnalysis right) = await new PgCatalogResolver().EnrichPairAsync(
            Parse("SELECT 1"), Parse("SELECT 1, 2"), Alias, session, CancellationToken.None);
        Assert.Contains("unsupported_construct", left.Ir.RiskCodes);
        Assert.Contains("unsupported_construct", right.Ir.RiskCodes);
        Assert.Contains("pg_catalog.pg_cast", Assert.Single(session.Sql));
    }

    [Fact]
    public async Task Legacy_ir_without_parser_proof_keeps_global_cast_check()
    {
        SqlIr ir = new("postgresql", ["Select"], [], [], [], [], [], false, false, [], [], "SELECT 1", "fp");
        MetadataSession session = new([new OracleScalarRow(false, null, null)]);
        Assert.False(await PgConversionSafety.IsSafeAsync([new SqlAnalysis(ir, true)], session, CancellationToken.None));
        Assert.Contains("pg_catalog.pg_cast", Assert.Single(session.Sql));
    }

    [Theory]
    [InlineData(0, true)]
    [InlineData(1, null)]
    [InlineData(1, false)]
    [InlineData(2, true)]
    public async Task Inconclusive_catalog_result_rejects_single_and_pair(int count, bool? safe)
    {
        SqlAnalysis analysis = Parse("SELECT '7'::integer");
        MetadataSession session = new(Enumerable.Repeat(new OracleScalarRow(safe, null, null), count).ToArray());
        PgCatalogResolver resolver = new();
        SqlAnalysis single = await resolver.EnrichAsync(analysis, Alias, session, CancellationToken.None);
        Assert.Contains("unsupported_construct", single.Ir.RiskCodes);
        Assert.Equal(analysis.Ir.TypeReferences, single.Ir.TypeReferences);

        (SqlAnalysis left, SqlAnalysis right) = await resolver.EnrichPairAsync(
            Parse("SELECT 1"), analysis, Alias, session, CancellationToken.None);
        Assert.Contains("unsupported_construct", left.Ir.RiskCodes);
        Assert.Contains("unsupported_construct", right.Ir.RiskCodes);
        Assert.Equal(analysis.Ir.TypeReferences, right.Ir.TypeReferences);
        Assert.Equal(2, session.Sql.Count);
        Assert.All(session.Sql, sql => Assert.DoesNotContain("SELECT '7'", sql));
    }

    [Fact]
    public async Task Pair_deduplicates_type_metadata_and_preserves_both_sides()
    {
        SqlAnalysis analysis = Parse("SELECT '7'::integer");
        MetadataSession session = new([new OracleScalarRow(true, null, null)]);
        (SqlAnalysis left, SqlAnalysis right) = await new PgCatalogResolver().EnrichPairAsync(
            analysis, analysis, Alias, session, CancellationToken.None);
        Assert.Empty(left.Ir.RiskCodes);
        Assert.Empty(right.Ir.RiskCodes);
        string sql = Assert.Single(session.Sql);
        Assert.Equal(1, sql.Split("'int4'::pg_catalog.name").Length - 1);
        Assert.Contains("pg_catalog.pg_cast", sql);
        Assert.Contains("t.typinput", sql);
        Assert.Contains("t.typoutput", sql);
        Assert.Contains("t.typmodin", sql);
        Assert.Contains("p.proallargtypes", sql);
        Assert.Contains("c.castfunc", sql);
    }

    [Fact]
    public async Task Delimited_type_component_cannot_be_reinterpreted_as_catalog_qualification()
    {
        MetadataSession session = new([new OracleScalarRow(true, null, null)]);
        SqlAnalysis result = await new PgCatalogResolver().EnrichAsync(
            Parse("SELECT 'x'::\"pg_catalog.text\""), Alias, session, CancellationToken.None);
        Assert.Contains("unsupported_construct", result.Ir.RiskCodes);
        Assert.Empty(session.Sql);
    }

    [Fact]
    public async Task Cancellation_precedes_conversion_metadata_read()
    {
        MetadataSession session = new([]);
        using CancellationTokenSource cancellation = new();
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => new PgCatalogResolver().EnrichAsync(
            Parse("SELECT '7'::integer"), Alias, session, cancellation.Token));
        Assert.Empty(session.Sql);
    }

    private static SqlAnalysis Parse(string sql)
    {
        SqlParseResult parsed = new LibPgQuerySqlParser().Parse(sql, CancellationToken.None);
        Assert.True(parsed.Success, parsed.RedactedMessage);
        return new SqlAnalysis(parsed.Ir!, true);
    }

    private sealed class MetadataSession(IReadOnlyList<OracleScalarRow> rows) : IReadOnlySession
    {
        public List<string> Sql { get; } = [];

        public Task ExecuteAsync(string sql, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("Only metadata reads are authorized in this test.");

        public Task<IReadOnlyList<OracleScalarRow>> ExecuteReaderAsync(
            string sql,
            IReadOnlyList<OracleScalarColumn> allowedColumns,
            CancellationToken cancellationToken)
        {
            Sql.Add(sql);
            Assert.Equal("v", Assert.Single(allowedColumns).Name);
            return Task.FromResult(rows);
        }

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}
