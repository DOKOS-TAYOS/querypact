using System.Collections;
using System.Reflection;
using Sav.Domain.Analysis;
using Sav.Domain.Attestations;

namespace Sav.Domain.Tests;

public sealed class SqlIrTests
{
    [Fact]
    public void SqlIr_collection_properties_are_readonly_lists()
    {
        foreach (PropertyInfo property in typeof(SqlIr).GetProperties())
        {
            if (!typeof(IEnumerable).IsAssignableFrom(property.PropertyType) ||
                property.PropertyType == typeof(string))
            {
                continue;
            }

            Assert.True(
                typeof(IReadOnlyList<string>).IsAssignableFrom(property.PropertyType),
                $"{property.Name} must be IReadOnlyList<string>");
            Assert.False(
                typeof(List<string>).IsAssignableFrom(property.PropertyType),
                $"{property.Name} must not expose List<string>");
        }
    }

    [Fact]
    public void SqlIr_constructor_copies_input_collections()
    {
        List<string> types = ["Select"];
        List<string> reads = ["users"];
        List<string> casts = ["pg_catalog.int4"];
        SqlIr ir = new(
            "postgresql",
            types,
            reads,
            [],
            ["id"],
            [],
            [],
            false,
            false,
            [],
            [],
            "SELECT id FROM users",
            "fp",
            operators: null,
            functionReferences: null,
            typeReferences: casts);

        types.Add("Delete");
        reads.Clear();
        casts.Clear();

        Assert.Equal(["Select"], ir.StatementTypes);
        Assert.Equal(["users"], ir.TablesRead);
        Assert.Equal(["pg_catalog.int4"], ir.TypeReferences);
        Assert.Contains("NormalizedSql", typeof(SqlIr).GetProperties().Select(p => p.Name));
    }

    [Fact]
    public void StructuralSqlIr_omits_normalized_sql_and_fingerprint()
    {
        string[] names = typeof(StructuralSqlIr).GetProperties().Select(p => p.Name).ToArray();
        Assert.DoesNotContain("NormalizedSql", names);
        Assert.DoesNotContain("Fingerprint", names);
        Assert.DoesNotContain("Operators", names);
        Assert.DoesNotContain("TypeReferences", names);
        Assert.DoesNotContain("Int4ConstantProjectionCount", names);
    }

    [Fact]
    public void SqlAnalysis_wraps_sql_ir()
    {
        SqlIr ir = new(
            "postgresql",
            ["Select"],
            [],
            [],
            [],
            [],
            [],
            false,
            false,
            [],
            [],
            "SELECT 1",
            "fp");
        SqlAnalysis analysis = new(ir, IsParsable: true);
        Assert.Same(ir, analysis.Ir);
        Assert.True(analysis.IsParsable);
    }
}
