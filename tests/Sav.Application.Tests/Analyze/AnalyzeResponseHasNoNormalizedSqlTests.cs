using System.Reflection;
using Sav.Application.Analyze;
using Sav.Domain.Attestations;
using Sav.Domain.Decisions;

namespace Sav.Application.Tests.Analyze;

public sealed class AnalyzeResponseHasNoNormalizedSqlTests
{
    [Fact]
    public void AnalyzeSqlResponse_type_graph_has_no_normalized_sql()
    {
        AssertNoNormalizedSql(typeof(AnalyzeSqlResponse));
        AssertNoNormalizedSql(typeof(AttestationAnalysis));
        AssertNoNormalizedSql(typeof(StructuralSqlIr));
    }

    [Fact]
    public async Task ExecuteAsync_response_excludes_normalized_sql_even_when_parser_had_it()
    {
        AnalyzeSqlUseCase useCase = new(
            new FakeParser(success: true, normalizedSql: "SELECT id FROM users WHERE email = 'canary@example.invalid'"),
            new FakePolicyEngine(PolicyOutcome.Allow),
            new FakePolicyLoader(),
            new FakeContractLoader(),
            new FakePathResolver(),
            new RecordingRedactor());

        AnalyzeSqlResponse response = await useCase.ExecuteAsync(
            new AnalyzeSqlRequest(
                "SELECT id FROM users WHERE email = 'canary@example.invalid'",
                "policies/demo.yaml",
                null),
            CancellationToken.None);

        string json = System.Text.Json.JsonSerializer.Serialize(response);
        Assert.DoesNotContain("NormalizedSql", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("canary@example.invalid", json, StringComparison.OrdinalIgnoreCase);
        Assert.Null(response.Analysis.Ir.GetType().GetProperty("NormalizedSql"));
    }

    private static void AssertNoNormalizedSql(Type type)
    {
        foreach (PropertyInfo property in type.GetProperties(BindingFlags.Instance | BindingFlags.Public))
        {
            Assert.False(
                string.Equals(property.Name, "NormalizedSql", StringComparison.Ordinal),
                $"{type.Name}.{property.Name} must not exist");
            if (property.PropertyType.Namespace?.StartsWith("Sav.", StringComparison.Ordinal) == true)
            {
                AssertNoNormalizedSql(property.PropertyType);
            }
        }
    }
}
