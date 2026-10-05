using System.Reflection;
using System.Text.Json;
using Sav.Application.Abstractions;
using Sav.Domain.Errors;
using Sav.Domain.Targets;
using Sav.Infrastructure.Postgres.Targets;
using Sav.Infrastructure.Postgres.Tests.Fixtures;
using Sav.Security.Tests.Bypass;
using Sav.Security.Tests.NoLeak;
using Sav.Security.Tests.Surface;

namespace Sav.Security.Tests.Benchmark;

[Collection(nameof(PostgresRoCollection))]
public sealed class SecurityBenchmarkMvpAWave2Tests
{
    private static readonly string[] RequiredCaseIds =
    [
        "notice_leakage_canary",
        "analyze_never_opens_pg",
        "readonly_insert_capable_no_temp_refused",
        "canary_trigger_side_effect_refuse",
        "oracle_template_bypass_query_succeeds_empty_result",
        "query_succeeds_no_row_leak",
        "empty_result_no_row_leak",
        "pool_checkout_reapplies_readonly",
        "diff-missing-table",
        "diff-renamed-relation",
        "diff-cte-base-missing",
        "diff-subquery-missing",
        "diff-write-target-missing",
        "pg_read_file_deny",
        "oracle_builtin_allowlist_excludes_dangerous",
    ];

    private readonly PostgresRoFixture _fixture;

    public SecurityBenchmarkMvpAWave2Tests(PostgresRoFixture fixture)
    {
        _fixture = fixture;
    }

    [Fact]
    public void Wave2_case_ids_are_present_and_harness_runs_green()
    {
        SecurityBenchmarkCorpus corpus = SecurityBenchmarkCorpus.LoadMvpA();
        HashSet<string> wave2Ids = corpus.Cases
            .Where(c => c.Wave == 2)
            .Select(c => c.Id)
            .ToHashSet(StringComparer.Ordinal);

        foreach (string id in RequiredCaseIds)
        {
            Assert.True(wave2Ids.Contains(id), "Missing wave-2 case id: " + id);
        }

        Assert.True(
            RequiredCaseIds.Count(id => id.StartsWith("diff-", StringComparison.Ordinal)) >= 5,
            "Expected ≥5 parser-catalog differential case ids.");

        Assert.All(corpus.Cases.Where(c => c.Wave == 2), c =>
        {
            Assert.False(string.IsNullOrWhiteSpace(c.OwnerTest));
            Assert.True(SecurityBenchmarkOwnerArtifacts.OwnerTestArtifactExists(c.OwnerTest), "Missing ownerTest artifact for " + c.Id + ": " + c.OwnerTest);
        });

        SecurityBenchmarkRunResult result = SecurityBenchmarkHarness.Run(corpus);
        Assert.True(result.Passed);
        Assert.Equal(0, result.OpenCriticalOrHighFailures);
    }

    [Theory]
    [MemberData(nameof(RequiredCaseIdData))]
    public async Task Wave2_case_runs_green(string caseId)
    {
        SecurityBenchmarkCorpus corpus = SecurityBenchmarkCorpus.LoadMvpA();
        SecurityBenchmarkCase c = Assert.Single(corpus.Cases, x => x.Id == caseId && x.Wave == 2);
        Assert.True(SecurityBenchmarkOwnerArtifacts.OwnerTestArtifactExists(c.OwnerTest), c.OwnerTest);
        await RunCaseAsync(caseId);
    }

    public static TheoryData<string> RequiredCaseIdData()
    {
        TheoryData<string> data = new();
        foreach (string id in RequiredCaseIds)
        {
            data.Add(id);
        }

        return data;
    }

    private async Task RunCaseAsync(string caseId)
    {
        switch (caseId)
        {
            case "notice_leakage_canary":
                new OracleNoticeLeakageTests(_fixture).Redact_egress_strips_notice_detail_and_canary();
                break;
            case "analyze_never_opens_pg":
                RunAnalyzeNeverOpensPg();
                break;
            case "readonly_insert_capable_no_temp_refused":
                await RunInsertCapableNoTempRefusedAsync();
                break;
            case "canary_trigger_side_effect_refuse":
                await new ReadOnlyCanaryTriggerSideEffectTests()
                    .Trigger_write_outside_probe_with_successful_canary_refuses_role_not_read_only();
                break;
            case "oracle_template_bypass_query_succeeds_empty_result":
                QuerySucceedsTemplateBypassTests templates = new();
                templates.Query_succeeds_template_always_wraps_agent_sql();
                templates.Empty_result_template_always_wraps_agent_sql();
                break;
            case "query_succeeds_no_row_leak":
                await new QuerySucceedsNoRowLeakTests(_fixture).Exists_scalar_path_never_leaks_row_payloads();
                break;
            case "empty_result_no_row_leak":
                await new EmptyResultNoRowLeakTests(_fixture).Not_exists_fail_path_never_leaks_row_payloads();
                break;
            case "pool_checkout_reapplies_readonly":
                await RunPoolCheckoutReappliesAsync();
                break;
            case "diff-missing-table":
            case "diff-renamed-relation":
            case "diff-cte-base-missing":
            case "diff-subquery-missing":
            case "diff-write-target-missing":
                AssertDifferentialSeedPresent(caseId);
                break;
            case "pg_read_file_deny":
                new OracleSqlBoundaryBypassTests().Rejects_pg_read_file_style_function();
                break;
            case "oracle_builtin_allowlist_excludes_dangerous":
                OracleBuiltinAllowListExclusionTests builtins = new();
                builtins.Dangerous_functions_are_absent_from_oracle_wrapper_builtin_allow_list("pg_read_file");
                builtins.Allow_list_is_frozen_empty_set();
                break;
            default:
                throw new InvalidOperationException("No runner for case: " + caseId);
        }
    }

    private async Task RunInsertCapableNoTempRefusedAsync()
    {
        await using ReadOnlySessionFactory factory = _fixture.CreateFactory();
        TargetAlias alias = _fixture.Resolve(PostgresRoFixture.WriterAlias);
        SavException ex = await Assert.ThrowsAsync<SavException>(
            () => factory.OpenReadOnlySessionAsync(alias, CancellationToken.None));
        Assert.Equal(SavErrorCode.RoleNotReadOnly, ex.Code);
    }

    private async Task RunPoolCheckoutReappliesAsync()
    {
        await using ReadOnlySessionFactory factory = _fixture.CreateFactory();
        TargetAlias alias = _fixture.Resolve(PostgresRoFixture.RoAlias);
        await using IReadOnlySession session =
            await factory.OpenReadOnlySessionAsync(alias, CancellationToken.None);

        IReadOnlyList<OracleScalarRow> first = await session.ExecuteReaderAsync(
            "SHOW transaction_read_only",
            [new OracleScalarColumn("transaction_read_only", OracleScalarKind.StringV)],
            CancellationToken.None);
        Assert.Equal("on", first[0].StringV, ignoreCase: true);

        IReadOnlyList<OracleScalarRow> second = await session.ExecuteReaderAsync(
            "SHOW transaction_read_only",
            [new OracleScalarColumn("transaction_read_only", OracleScalarKind.StringV)],
            CancellationToken.None);
        Assert.Equal("on", second[0].StringV, ignoreCase: true);

        await Assert.ThrowsAsync<SavException>(
            () => session.ExecuteAsync(
                "INSERT INTO public.sav_ro_probe(probe_key) VALUES ('should-fail')",
                CancellationToken.None));
    }

    private static void RunAnalyzeNeverOpensPg()
    {
        ConstructorInfo ctor = typeof(Sav.Application.Analyze.AnalyzeSqlUseCase).GetConstructors().Single();
        foreach (ParameterInfo parameter in ctor.GetParameters())
        {
            Assert.NotEqual(typeof(IReadOnlySessionFactory), parameter.ParameterType);
            Assert.NotEqual(typeof(IReadOnlySession), parameter.ParameterType);
            Assert.DoesNotContain("Npgsql", parameter.ParameterType.FullName ?? string.Empty, StringComparison.Ordinal);
        }
    }

    private static void AssertDifferentialSeedPresent(string seedId)
    {
        string path = Path.Combine(
            global::Sav.Security.Tests.SecurityAnalyzeHarness.FindRepoRoot(),
            "tests",
            "fixtures",
            "sql",
            "parser-catalog-differential-seeds.json");
        using JsonDocument doc = JsonDocument.Parse(File.ReadAllText(path));
        HashSet<string> ids = doc.RootElement.GetProperty("cases")
            .EnumerateArray()
            .Select(e => e.GetProperty("id").GetString()!)
            .ToHashSet(StringComparer.Ordinal);
        Assert.True(ids.Contains(seedId), "Missing differential seed: " + seedId);
        Assert.True(ids.Count >= 5);
    }
}
