using Sav.Application.Tests.Verify;
using Sav.Infrastructure.Postgres.Tests.Fixtures;
using Sav.Security.Tests.Authorize;
using Sav.Security.Tests.Bypass;
using Sav.Security.Tests.NoLeak;
using Sav.Security.Tests.Surface;

namespace Sav.Security.Tests.Benchmark;

/// <summary>
/// M010a-B: MVP-B security corpus index. Required case IDs present and owner paths green.
/// Does not remediate findings (M010b-B).
/// </summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class SecurityBenchmarkMvpBCollection : ICollectionFixture<PostgresRoFixture>
{
    public const string Name = "SavSecurityBenchmarkMvpB";
}

[Collection(SecurityBenchmarkMvpBCollection.Name)]
public sealed class SecurityBenchmarkMvpBTests
{
    private static readonly string[] RequiredCaseIds =
    [
        "unique_non_null_identifier_injection",
        "unique_non_null_no_row_leak",
        "unique_non_null_notice_leakage",
        "verify_migration_never_real_alias",
        "verify_migration_policy_before_apply",
        "oracle_template_bypass_query_equivalent",
        "schema_orphan_identifier_bypass",
        "affected_rows_exact_shape",
        "affected_rows_never_real_alias",
        "schema_orphan_forbidden_on_verify_query",
        "egress_verify_equivalence_host_di",
        "egress_verify_migration_host_di",
        "egress_cli_verify_equivalence_and_migration",
        "egress_mcp_verify_equivalence_and_migration",
    ];

    private readonly PostgresRoFixture _fixture;

    public SecurityBenchmarkMvpBTests(PostgresRoFixture fixture)
    {
        _fixture = fixture;
    }

    [Fact]
    public void Mvp_b_case_ids_are_present_and_harness_runs_green()
    {
        SecurityBenchmarkCorpus corpus = SecurityBenchmarkCorpus.LoadMvpB();
        Assert.Equal(1, corpus.SchemaVersion);
        Assert.Equal("MVP-B", corpus.Band);

        HashSet<string> ids = corpus.Cases
            .Select(c => c.Id)
            .ToHashSet(StringComparer.Ordinal);

        foreach (string id in RequiredCaseIds)
        {
            Assert.True(ids.Contains(id), "Missing MVP-B case id: " + id);
        }

        Assert.All(corpus.Cases, c =>
        {
            Assert.False(string.IsNullOrWhiteSpace(c.OwnerTest));
            Assert.True(
                SecurityBenchmarkOwnerArtifacts.OwnerTestArtifactExists(c.OwnerTest),
                "Missing ownerTest artifact for " + c.Id + ": " + c.OwnerTest);
        });

        SecurityBenchmarkRunResult result = SecurityBenchmarkHarness.Run(corpus);
        Assert.True(result.Passed);
        Assert.Equal(corpus.Cases.Length, result.CaseCount);
        Assert.Equal(0, result.OpenCriticalOrHighFailures);
        Assert.True(corpus.Cases.Length >= RequiredCaseIds.Length);
    }

    [Theory]
    [MemberData(nameof(RequiredCaseIdData))]
    public async Task Mvp_b_case_runs_green(string caseId)
    {
        SecurityBenchmarkCorpus corpus = SecurityBenchmarkCorpus.LoadMvpB();
        SecurityBenchmarkCase c = Assert.Single(corpus.Cases, x => x.Id == caseId);
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
            case "unique_non_null_identifier_injection":
                UniqueNonNullIdentifierBypassTests injection = new();
                injection.Unique_template_rejects_unsafe_column_identifiers(
                    "col); SELECT pg_read_file('pg_hba.conf')");
                injection.Unique_template_quotes_safe_column();
                injection.Non_null_template_quotes_safe_column();
                break;
            case "unique_non_null_no_row_leak":
                UniqueNonNullNoRowLeakTests noLeak = new(_fixture);
                await noLeak.Unique_fail_never_leaks_row_payload_or_count();
                await noLeak.Non_null_fail_never_leaks_null_count();
                break;
            case "unique_non_null_notice_leakage":
                await new UniqueNonNullNoticeLeakageTests(_fixture)
                    .Raise_exception_canary_redacted_on_unique_path();
                break;
            case "verify_migration_never_real_alias":
                VerifyMigrationNeverUsesRealAliasE2ETests migrationAlias = new();
                migrationAlias.Request_cli_and_tool_surfaces_have_no_target_alias_hook();
                await migrationAlias.Host_di_allow_path_uses_ephemeral_fingerprint_and_never_resolves_aliases();
                break;
            case "verify_migration_policy_before_apply":
                VerifyMigrationDeniesBeforeApplyTests policy = new();
                await policy.Denied_migration_fixtures_never_invoke_shadow("copy.sql");
                await policy.Denied_migration_fixtures_never_invoke_shadow("create-extension.sql");
                await policy.Denied_migration_fixtures_never_invoke_shadow("multi-statement.sql");
                await policy.Denied_migration_fixtures_never_invoke_shadow("unparsable.sql");
                await policy.Denied_migration_fixtures_never_invoke_shadow("denied-table.sql");
                break;
            case "oracle_template_bypass_query_equivalent":
                QueryEquivalentTemplateBypassTests eq = new();
                eq.Except_all_templates_wrap_both_directions_as_count_only();
                eq.Equivalence_pair_rejects_multi_statement_left();
                eq.Equivalence_pair_rejects_dml_markers_in_right();
                eq.Equivalence_pair_rejects_write_ir();
                break;
            case "schema_orphan_identifier_bypass":
                SchemaOrphanIdentifierBypassTests schemaBypass = new();
                schemaBypass.No_new_orphans_rejects_unsafe_parent_table(
                    "orders); SELECT pg_read_file('pg_hba.conf')");
                schemaBypass.No_new_orphans_quotes_safe_identifiers_in_count_template();
                schemaBypass.Schema_invariant_rejects_unsafe_relation_name("orders); DROP TABLE t");
                break;
            case "affected_rows_exact_shape":
                AffectedRowsExactShapeTests shape = new();
                shape.Affected_rows_template_is_direct_dml_without_select_wrapper();
                shape.Multi_statement_dml_is_rejected();
                break;
            case "affected_rows_never_real_alias":
                await new AffectedRowsNeverUsesRealAliasTests(_fixture)
                    .Real_alias_returns_property_environment_forbidden_before_execute();
                break;
            case "schema_orphan_forbidden_on_verify_query":
                await new VerifyQuerySchemaPropsForbiddenOnRealAliasTests()
                    .Schema_invariant_and_orphans_on_real_alias_are_property_environment_forbidden();
                break;
            case "egress_verify_equivalence_host_di":
                await new AllEgressPathsRedactObjectVerifyHostTests()
                    .VerifyEquivalenceResponse_via_host_di_calls_RedactObject();
                break;
            case "egress_verify_migration_host_di":
                await new AllEgressPathsRedactObjectVerifyHostTests()
                    .VerifyMigrationResponse_via_host_di_calls_RedactObject();
                break;
            case "egress_cli_verify_equivalence_and_migration":
                new AllEgressPathsRedactObjectVerifyHostTests()
                    .Cli_verify_equivalence_and_migration_stdout_json_are_redacted();
                break;
            case "egress_mcp_verify_equivalence_and_migration":
                await new AllEgressPathsRedactObjectVerifyHostTests()
                    .Mcp_verify_equivalence_and_migration_json_are_redacted();
                break;
            default:
                throw new InvalidOperationException("No runner for case: " + caseId);
        }
    }
}
