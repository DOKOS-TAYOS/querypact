using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.DependencyInjection;
using Sav.Application.Abstractions;
using Sav.Application.Analyze;
using Sav.Domain.Decisions;
using Sav.Domain.Errors;
using Sav.Host.Composition;
using Sav.Host.Configuration;
using Sav.Host.Mcp;
using Sav.Host.Mcp.Tools;
using Sav.Infrastructure.Postgres.Oracle;
using Sav.Infrastructure.Postgres.Parsing;
using Sav.Infrastructure.Postgres.Targets;
using Sav.Infrastructure.Storage.Attestations;
using Sav.Security.Tests.NoLeak;

namespace Sav.Security.Tests.Benchmark;

public sealed class SecurityBenchmarkMvpAWave1Tests
{
    private static readonly string[] RequiredCaseIds =
    [
        "multi_statement_bypass",
        "cte_write_smuggle",
        "policy_path_traversal_cli",
        "policy_path_traversal_mcp",
        "attestation_id_path_traversal",
        "agent_supplied_dsn_rejection",
        "execute_sql_absence",
        "explain_analyze_absence",
        "attestation_hmac_tamper",
        "attestation_hmac_matches_redacted_egress",
        "hmac_key_too_weak_startup",
    ];

    [Fact]
    public void Wave1_case_ids_are_present_and_harness_runs_green()
    {
        SecurityBenchmarkCorpus corpus = SecurityBenchmarkCorpus.LoadMvpA();
        HashSet<string> wave1Ids = corpus.Cases
            .Where(c => c.Wave == 1)
            .Select(c => c.Id)
            .ToHashSet(StringComparer.Ordinal);

        foreach (string id in RequiredCaseIds)
        {
            Assert.True(wave1Ids.Contains(id), "Missing wave-1 case id: " + id);
        }

        Assert.All(corpus.Cases.Where(c => c.Wave == 1), c =>
        {
            Assert.False(string.IsNullOrWhiteSpace(c.OwnerTest));
            Assert.True(SecurityBenchmarkOwnerArtifacts.OwnerTestArtifactExists(c.OwnerTest), "Missing ownerTest artifact for " + c.Id + ": " + c.OwnerTest);
        });

        SecurityBenchmarkRunResult result = SecurityBenchmarkHarness.Run(corpus);
        Assert.True(result.Passed);
        Assert.Equal(corpus.Cases.Length, result.CaseCount);
        Assert.Equal(0, result.OpenCriticalOrHighFailures);
    }

    [Theory]
    [MemberData(nameof(RequiredCaseIdData))]
    public async Task Wave1_case_runs_green(string caseId)
    {
        SecurityBenchmarkCorpus corpus = SecurityBenchmarkCorpus.LoadMvpA();
        SecurityBenchmarkCase c = Assert.Single(corpus.Cases, x => x.Id == caseId && x.Wave == 1);
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
        switch (caseId)
        {
            case "multi_statement_bypass":
                await RunMultiStatementBypassAsync();
                break;
            case "cte_write_smuggle":
                await RunCteWriteSmuggleAsync();
                break;
            case "policy_path_traversal_cli":
            case "policy_path_traversal_mcp":
                await RunPolicyPathTraversalAsync();
                break;
            case "attestation_id_path_traversal":
                AttestationIdGuard.EnsureValid("ok-id_01");
                SavException idEx = Assert.Throws<SavException>(() => AttestationIdGuard.EnsureValid("../etc/passwd"));
                Assert.Equal(SavErrorCode.AttestationIdInvalid, idEx.Code);
                break;
            case "agent_supplied_dsn_rejection":
                RunAgentDsnRejection();
                break;
            case "execute_sql_absence":
                Assert.DoesNotContain("execute_sql", SavMcpServer.GetToolNames(DiProfile.AnalyzeOnly));
                Assert.DoesNotContain("execute_sql", SavMcpServer.GetToolNames(DiProfile.Full));
                break;
            case "explain_analyze_absence":
                RunExplainAnalyzeAbsence();
                break;
            case "attestation_hmac_tamper":
                RunHmacTamper();
                break;
            case "attestation_hmac_matches_redacted_egress":
                new AttestationHmacMatchesRedactedEgressTests()
                    .Hmac_matches_redacted_body_and_rejects_post_sign_mutation();
                break;
            case "hmac_key_too_weak_startup":
                RunHmacKeyTooWeak();
                break;
            default:
                throw new InvalidOperationException("No runner for case: " + caseId);
        }
    }

    private static async Task RunMultiStatementBypassAsync()
    {
        using SecurityAnalyzeHarness.TempPolicyRoot root =
            SecurityAnalyzeHarness.CreatePolicyRoot("security-deny-secrets.yaml");
        AnalyzeSqlUseCase useCase = SecurityAnalyzeHarness.CreateUseCase(root.Path);
        AnalyzeSqlResponse response = await useCase.ExecuteAsync(
            new AnalyzeSqlRequest(
                SecurityAnalyzeHarness.CorpusSql("bypass_multi_statement"),
                root.PolicyRelativePath,
                null),
            CancellationToken.None);
        Assert.Equal(PolicyOutcome.Deny, response.Decision.Outcome);
        Assert.Contains("multiple_statements", response.Decision.RuleIds);
    }

    private static async Task RunCteWriteSmuggleAsync()
    {
        const string sql = "WITH x AS (INSERT INTO t(v) VALUES ('x') RETURNING v) SELECT v FROM x";
        ISqlParser parser = new LibPgQuerySqlParser();

        SqlParseResult benign = parser.Parse("SELECT 1", CancellationToken.None);
        Assert.True(benign.Success);
        Assert.NotNull(benign.Ir);
        Assert.DoesNotContain("unsupported_construct", benign.Ir.RiskCodes);

        SqlParseResult parsed = parser.Parse(sql, CancellationToken.None);
        Assert.True(parsed.Success);
        Assert.NotNull(parsed.Ir);
        Assert.NotEmpty(parsed.Ir.TablesWritten);
        Assert.Contains("unsupported_construct", parsed.Ir.RiskCodes);

        using SecurityAnalyzeHarness.TempPolicyRoot root =
            SecurityAnalyzeHarness.CreatePolicyRoot("security-deny-secrets.yaml");
        AnalyzeSqlUseCase useCase = SecurityAnalyzeHarness.CreateUseCase(root.Path);
        AnalyzeSqlResponse benignResponse = await useCase.ExecuteAsync(
            new AnalyzeSqlRequest("SELECT 1", root.PolicyRelativePath, null),
            CancellationToken.None);
        Assert.Equal(PolicyOutcome.Allow, benignResponse.Decision.Outcome);

        AnalyzeSqlResponse response = await useCase.ExecuteAsync(
            new AnalyzeSqlRequest(sql, root.PolicyRelativePath, null),
            CancellationToken.None);
        Assert.Equal(PolicyOutcome.Deny, response.Decision.Outcome);
        Assert.Contains("unsupported_construct", response.Decision.RuleIds);

        SavException ex = Assert.Throws<SavException>(
            () => OracleSqlBoundary.BuildWrappedCommand(
                OracleSqlTemplateKind.QuerySucceedsExists,
                parsed.Ir,
                sql,
                policyAllowedFunctions: []));
        Assert.Equal(SavErrorCode.UnsupportedConstruct, ex.Code);
    }

    private static async Task RunPolicyPathTraversalAsync()
    {
        using SecurityAnalyzeHarness.TempPolicyRoot root =
            SecurityAnalyzeHarness.CreatePolicyRoot("security-deny-secrets.yaml");
        AnalyzeSqlUseCase useCase = SecurityAnalyzeHarness.CreateUseCase(root.Path);
        SavException ex = await Assert.ThrowsAsync<SavException>(() =>
            useCase.ExecuteAsync(
                new AnalyzeSqlRequest("SELECT 1", "../outside.yaml", null),
                CancellationToken.None));
        Assert.Equal(SavErrorCode.PathNotAllowed, ex.Code);

        AnalyzeSqlTool tool = new(useCase);
        string json = await tool.AnalyzeSql("SELECT 1", "../outside.yaml", null, CancellationToken.None);
        Assert.Contains(SavErrorCode.PathNotAllowed, json, StringComparison.Ordinal);
    }

    private static void RunAgentDsnRejection()
    {
        TargetAliasResolver resolver = new(new TargetsBindingOptions(new Dictionary<string, string>
        {
            ["prod_ro"] = "SAV_TARGET_PROD_RO_DSN",
        }));
        SavException ex = Assert.Throws<SavException>(
            () => resolver.Resolve("Host=evil;Username=a;Password=b;Database=db"));
        Assert.Equal(SavErrorCode.AliasLooksLikeDsn, ex.Code);
        Assert.DoesNotContain("Password=", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    private static void RunExplainAnalyzeAbsence()
    {
        string repo = global::Sav.Security.Tests.SecurityAnalyzeHarness.FindRepoRoot();
        string[] paths =
        [
            Path.Combine(repo, "src", "Sav.Infrastructure.Postgres", "Plans", "ExplainPlanProvider.cs"),
            Path.Combine(repo, "src", "Sav.Application", "Analyze", "AnalyzeSqlUseCase.cs"),
            Path.Combine(repo, "src", "Sav.Application", "Verify", "VerifyQueryUseCase.cs"),
            Path.Combine(repo, "src", "Sav.Host", "Cli", "AnalyzeCommand.cs"),
            Path.Combine(repo, "src", "Sav.Host", "Cli", "VerifyQueryCommand.cs"),
            Path.Combine(repo, "src", "Sav.Host", "Mcp", "Tools", "AnalyzeSqlTool.cs"),
        ];

        foreach (string path in paths)
        {
            Assert.True(File.Exists(path), "Missing source: " + path);
            string text = File.ReadAllText(path);
            Assert.DoesNotContain("EXPLAIN ANALYZE", text, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("EXPLAIN (ANALYZE", text, StringComparison.OrdinalIgnoreCase);
        }
    }

    private static void RunHmacTamper()
    {
        byte[] key = Enumerable.Repeat((byte)0x42, 32).ToArray();
        IAttestationMac mac = new AttestationHmac();
        byte[] body = Encoding.UTF8.GetBytes("""{"decision":"PASS","sqlHash":"abc"}""");
        string original = mac.ComputeBase64(body, key);
        byte[] tampered = (byte[])body.Clone();
        tampered[0] ^= 0x01;
        string after = mac.ComputeBase64(tampered, key);
        Assert.NotEqual(original, after);
        Assert.False(CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(original),
            Encoding.UTF8.GetBytes(after)));
    }

    private static void RunHmacKeyTooWeak()
    {
        SavException decodeEx = Assert.Throws<SavException>(() =>
            AttestationHmacKeyDecoder.Decode("base64:" + Convert.ToBase64String(new byte[8])));
        Assert.Equal(SavErrorCode.AttestationHmacKeyTooWeak, decodeEx.Code);

        ServiceCollection services = new();
        SavModeOptions options = new()
        {
            Mode = DiProfile.Full,
            ConfigRoot = Path.GetTempPath(),
            AttestationStoreRoot = Path.Combine(Path.GetTempPath(), "sav-attest-" + Guid.NewGuid().ToString("N")),
        };
        SavException diEx = Assert.Throws<SavException>(() => services.AddSavFull(options, new byte[8]));
        Assert.Equal(SavErrorCode.AttestationHmacKeyTooWeak, diEx.Code);
    }
}
