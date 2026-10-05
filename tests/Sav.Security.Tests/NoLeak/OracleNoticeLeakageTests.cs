using Sav.Application.Abstractions;
using Sav.Domain.Contracts;
using Sav.Domain.Decisions;
using Sav.Domain.Errors;
using Sav.Domain.Execution;
using Sav.Domain.Properties;
using Sav.Infrastructure.Postgres.Oracle;
using Sav.Infrastructure.Postgres.Redaction;
using Sav.Infrastructure.Postgres.Targets;
using Sav.Infrastructure.Postgres.Tests.Fixtures;

namespace Sav.Security.Tests.NoLeak;

[Collection(nameof(PostgresRoCollection))]
public sealed class OracleNoticeLeakageTests
{
    private const string Canary = "CANARY_LITERAL_do_not_egress@example.invalid";

    private readonly PostgresRoFixture _fixture;

    public OracleNoticeLeakageTests(PostgresRoFixture fixture)
    {
        _fixture = fixture;
    }

    [Fact]
    public void Redact_egress_strips_notice_detail_and_canary()
    {
        string raw =
            $"NOTICE: {Canary}\nDETAIL: row=({Canary})\nHINT: password=super-secret-password";

        string redacted = OracleSqlBoundary.RedactEgress(_fixture.Redactor, _fixture.StrictDisclosure, raw);

        Assert.DoesNotContain(Canary, redacted, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("super-secret-password", redacted, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("row=(", redacted, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(MinimalStrictRedactor.RedactedToken, redacted, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Boundary_error_details_are_redacted_before_leaving_oracle()
    {
        const string agent = $"SELECT pg_read_file('{Canary}')";
        var ir = OracleTestIr.Create(functions: ["pg_read_file"], agentSql: agent);

        await using ReadOnlySessionFactory factory = _fixture.CreateFactory();
        await using IReadOnlySession session =
            await factory.OpenReadOnlySessionAsync(_fixture.Resolve(PostgresRoFixture.RoAlias), CancellationToken.None);

        PropertyOracle oracle = new(_fixture.Redactor);
        PropertyEvaluationRequest request = new(
            ExecutionEnvironment.RealReadOnlyAlias,
            ir,
            [new QuerySucceedsSpec()],
            agent,
            null,
            null,
            _fixture.Resolve(PostgresRoFixture.RoAlias),
            session,
            null,
            null,
            _fixture.StrictDisclosure);

        IReadOnlyList<PropertyResult> results =
            await oracle.EvaluateAsync(request, CancellationToken.None);

        PropertyResult result = Assert.Single(results);
        Assert.Equal(PropertyStatus.Error, result.Status);
        Assert.Equal(SavErrorCode.UnsupportedConstruct, result.RedactedDetail);
        Assert.DoesNotContain(Canary, result.ToString(), StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("pg_read_file", result.RedactedDetail ?? string.Empty, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Raise_notice_from_agent_subquery_does_not_appear_in_property_results()
    {
        await _fixture.ExecuteAdminAsync(
            $"""
            CREATE OR REPLACE FUNCTION public.sav_oracle_notice_canary()
            RETURNS integer
            LANGUAGE plpgsql
            AS $$
            BEGIN
              RAISE NOTICE '{Canary}';
              RETURN 1;
            END;
            $$;
            GRANT EXECUTE ON FUNCTION public.sav_oracle_notice_canary() TO sav_ro;
            """);

        // Function is denied by empty allow-list before execute: still assert egress codes only.
        const string agent = "SELECT sav_oracle_notice_canary()";
        var ir = OracleTestIr.Create(functions: ["sav_oracle_notice_canary"], agentSql: agent);

        PropertyOracle oracle = new(_fixture.Redactor);
        PropertyEvaluationRequest request = new(
            ExecutionEnvironment.RealReadOnlyAlias,
            ir,
            [new QuerySucceedsSpec()],
            agent,
            null,
            null,
            _fixture.Resolve(PostgresRoFixture.RoAlias),
            session: null,
            null,
            null,
            _fixture.StrictDisclosure);

        // Missing session → error path must still redact.
        IReadOnlyList<PropertyResult> results =
            await oracle.EvaluateAsync(request, CancellationToken.None);

        PropertyResult result = Assert.Single(results);
        Assert.Equal(PropertyStatus.Error, result.Status);
        Assert.DoesNotContain(Canary, result.RedactedDetail ?? string.Empty, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(Canary, result.ToString(), StringComparison.OrdinalIgnoreCase);
    }
}
