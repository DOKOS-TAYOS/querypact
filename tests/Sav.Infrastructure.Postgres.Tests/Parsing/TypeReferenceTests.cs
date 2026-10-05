using Google.Protobuf;
using PgSqlParser;
using Sav.Application.Abstractions;
using Sav.Infrastructure.Postgres.Parsing;

namespace Sav.Infrastructure.Postgres.Tests.Parsing;

public sealed class TypeReferenceTests
{
    [Theory]
    [InlineData("SELECT CAST('7' AS integer)", "pg_catalog.int4")]
    [InlineData("SELECT '7'::pg_catalog.int4", "pg_catalog.int4")]
    [InlineData("SELECT CAST('x' AS varchar(8))", "pg_catalog.varchar")]
    [InlineData("SELECT ARRAY[1, 2]::integer[][]", "pg_catalog.int4[]")]
    [InlineData("SELECT DATE '2026-10-02'", "date")]
    [InlineData("SELECT 'x'::public.label", "public.label")]
    [InlineData("SELECT 'x'::\"pg_catalog.text\"", "\"pg_catalog.text\"")]
    public void Retains_type_identity_and_array_element_name(string sql, string expected)
    {
        SqlParseResult parsed = new LibPgQuerySqlParser().Parse(sql, CancellationToken.None);
        Assert.True(parsed.Success, parsed.RedactedMessage);
        Assert.Equal([expected], parsed.Ir!.TypeReferences);
        Assert.Empty(parsed.Ir.RiskCodes);
    }

    [Fact]
    public void Retains_nested_casts_inside_ctes_and_function_arguments()
    {
        SqlParseResult parsed = new LibPgQuerySqlParser().Parse(
            "WITH q AS (SELECT '7'::integer AS id) SELECT length(id::text)::bigint FROM q",
            CancellationToken.None);
        Assert.True(parsed.Success, parsed.RedactedMessage);
        Assert.Equal(["pg_catalog.int4", "pg_catalog.int8", "text"], parsed.Ir!.TypeReferences);
    }

    [Fact]
    public void Unmapped_type_identity_fails_closed()
    {
        var parsed = Parser.Parse("SELECT '7'::integer");
        Assert.Null(parsed.Error);
        ParseResult tree = parsed.Value!;
        TypeName type = FindType(tree)!;
        Assert.NotNull(type);
        type.Names.Clear();
        Assert.Contains("unsupported_construct", SqlIrMapper.Map(tree).RiskCodes);
    }

    [Fact]
    public void Delimited_type_name_function_syntax_fails_closed()
    {
        SqlParseResult parsed = new LibPgQuerySqlParser().Parse(
            "SELECT \"pg_catalog.text\"('ok')", CancellationToken.None);
        Assert.True(parsed.Success, parsed.RedactedMessage);
        Assert.Contains("unsupported_construct", parsed.Ir!.RiskCodes);
    }

    private static TypeName? FindType(IMessage message)
    {
        if (message is TypeName type)
        {
            return type;
        }

        foreach (var field in message.Descriptor.Fields.InFieldNumberOrder())
        {
            if (field.FieldType != Google.Protobuf.Reflection.FieldType.Message)
            {
                continue;
            }

            if (field.IsRepeated)
            {
                foreach (IMessage child in (System.Collections.IEnumerable)field.Accessor.GetValue(message))
                {
                    if (FindType(child) is TypeName found)
                    {
                        return found;
                    }
                }
            }
            else if (field.Accessor.HasValue(message) && field.Accessor.GetValue(message) is IMessage child &&
                     FindType(child) is TypeName found)
            {
                return found;
            }
        }

        return null;
    }
}
