using Microsoft.Extensions.DependencyInjection;
using Sav.Application.Abstractions;
using Sav.Domain.Errors;
using Sav.Host;
using Sav.Host.Composition;
using Sav.Host.Configuration;
using Sav.Host.Mcp;
using Sav.Infrastructure.Postgres.Redaction;
using Sav.Security.Tests.Surface;

namespace Sav.Security.Tests.Benchmark;

[Collection(Sav.Security.Tests.Surface.SecurityEnvCollectionDefinition.Name)]
public sealed class SecurityBenchmarkMvpAWave3Tests
{
    private static readonly string[] RequiredCaseIds =
    [
        "full_missing_hmac_refuses_startup",
        "analyze_only_starts_without_hmac",
        "analyze_only_tools_exclude_verify_and_get",
        "no_passthrough_redactor_host_di",
        "egress_analyze_sql_host_di",
        "egress_verify_query_host_di",
        "egress_get_attestation_host_di",
        "egress_cli_analyze",
        "egress_cli_verify_and_get",
        "egress_mcp_mvp_a",
    ];

    [Fact]
    public void Wave3_case_ids_are_present_and_harness_runs_green()
    {
        SecurityBenchmarkCorpus corpus = SecurityBenchmarkCorpus.LoadMvpA();
        HashSet<string> wave3Ids = corpus.Cases
            .Where(c => c.Wave == 3)
            .Select(c => c.Id)
            .ToHashSet(StringComparer.Ordinal);

        foreach (string id in RequiredCaseIds)
        {
            Assert.True(wave3Ids.Contains(id), "Missing wave-3 case id: " + id);
        }

        Assert.All(corpus.Cases.Where(c => c.Wave == 3), c =>
        {
            Assert.False(string.IsNullOrWhiteSpace(c.OwnerTest));
            Assert.True(SecurityBenchmarkOwnerArtifacts.OwnerTestArtifactExists(c.OwnerTest), "Missing ownerTest artifact for " + c.Id + ": " + c.OwnerTest);
        });

        SecurityBenchmarkRunResult result = SecurityBenchmarkHarness.Run(corpus);
        Assert.True(result.Passed);
        Assert.Equal(0, result.OpenCriticalOrHighFailures);
    }

    [Fact]
    public void Union_of_waves_1_2_3_is_non_empty_mvp_a_corpus_bar()
    {
        SecurityBenchmarkCorpus corpus = SecurityBenchmarkCorpus.LoadMvpA();
        Assert.Contains(corpus.Cases, c => c.Wave == 1);
        Assert.Contains(corpus.Cases, c => c.Wave == 2);
        Assert.Contains(corpus.Cases, c => c.Wave == 3);
        Assert.True(corpus.Cases.Length >= 26, "Expected w1+w2+w3 corpus size ≥ 26, got " + corpus.Cases.Length);
        Assert.Equal(0, corpus.Cases.Count(c => c.Wave is < 1 or > 3));
    }

    [Theory]
    [MemberData(nameof(RequiredCaseIdData))]
    public async Task Wave3_case_runs_green(string caseId)
    {
        SecurityBenchmarkCorpus corpus = SecurityBenchmarkCorpus.LoadMvpA();
        SecurityBenchmarkCase c = Assert.Single(corpus.Cases, x => x.Id == caseId && x.Wave == 3);
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

    private static async Task RunCaseAsync(string caseId)
    {
        AllEgressPathsRedactObjectMvpATests egress = new();
        switch (caseId)
        {
            case "full_missing_hmac_refuses_startup":
                RunFullMissingHmac();
                break;
            case "analyze_only_starts_without_hmac":
                RunAnalyzeOnlyStartsWithoutHmac();
                break;
            case "analyze_only_tools_exclude_verify_and_get":
                RunAnalyzeOnlyExcludesVerifyAndGet();
                break;
            case "no_passthrough_redactor_host_di":
                RunNoPassThroughRedactor();
                break;
            case "egress_analyze_sql_host_di":
                await egress.AnalyzeSqlResponse_via_host_di_calls_RedactObject();
                break;
            case "egress_verify_query_host_di":
                await egress.VerifyQueryResponse_via_host_di_calls_RedactObject();
                break;
            case "egress_get_attestation_host_di":
                await egress.GetAttestation_via_host_di_calls_RedactObject();
                break;
            case "egress_cli_analyze":
                egress.Cli_analyze_stdout_json_is_redacted();
                break;
            case "egress_cli_verify_and_get":
                egress.Cli_verify_query_and_attestation_get_stdout_json_are_redacted();
                break;
            case "egress_mcp_mvp_a":
                await egress.Mcp_analyze_verify_and_get_json_are_redacted();
                break;
            default:
                throw new InvalidOperationException("No runner for case: " + caseId);
        }
    }

    private static void RunFullMissingHmac()
    {
        ServiceCollection services = new();
        SavModeOptions options = new()
        {
            Mode = DiProfile.Full,
            ConfigRoot = Path.GetTempPath(),
            AttestationStoreRoot = Path.Combine(Path.GetTempPath(), "sav-attest-" + Guid.NewGuid().ToString("N")),
        };
        SavException ex = Assert.Throws<SavException>(() => services.AddSavByProfile(options, hmacKey: null));
        Assert.Equal(SavErrorCode.AttestationHmacKeyMissing, ex.Code);
    }

    private static void RunAnalyzeOnlyStartsWithoutHmac()
    {
        using ServiceProvider sp = Program.BuildServiceProvider(
            DiProfile.AnalyzeOnly,
            options: new SavModeOptions { Mode = DiProfile.AnalyzeOnly, ConfigRoot = Path.GetTempPath() },
            hmacKey: null);
        Assert.NotNull(sp.GetService<IAnalyzeSqlUseCase>());
        Assert.Null(sp.GetService<IAttestationMac>());
        Assert.Null(sp.GetService<IAttestationStore>());
    }

    private static void RunAnalyzeOnlyExcludesVerifyAndGet()
    {
        using ServiceProvider sp = Program.BuildServiceProvider(
            DiProfile.AnalyzeOnly,
            options: new SavModeOptions { Mode = DiProfile.AnalyzeOnly, ConfigRoot = Path.GetTempPath() });

        Assert.Null(sp.GetService<IVerifyQueryUseCase>());
        Assert.Null(sp.GetService<IVerifyEquivalenceUseCase>());
        Assert.Null(sp.GetService<IVerifyMigrationUseCase>());
        Assert.Null(sp.GetService<IGetAttestationUseCase>());
        Assert.Null(sp.GetService<IAttestationStore>());

        IReadOnlyList<string> tools = SavMcpServer.GetToolNames(DiProfile.AnalyzeOnly);
        Assert.Equal(["analyze_sql"], tools);
        Assert.DoesNotContain("verify_query", tools);
        Assert.DoesNotContain("verify_equivalence", tools);
        Assert.DoesNotContain("verify_migration", tools);
        Assert.DoesNotContain("get_attestation", tools);
    }

    private static void RunNoPassThroughRedactor()
    {
        using ServiceProvider sp = Program.BuildServiceProvider(
            DiProfile.AnalyzeOnly,
            options: new SavModeOptions { Mode = DiProfile.AnalyzeOnly, ConfigRoot = Path.GetTempPath() });
        IRedactor redactor = sp.GetRequiredService<IRedactor>();
        Assert.IsType<PostgresErrorRedactor>(redactor);
        Assert.DoesNotContain("PassThrough", redactor.GetType().Name, StringComparison.Ordinal);
    }
}
