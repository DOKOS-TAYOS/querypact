using System.Diagnostics;
using Sav.Application.Abstractions;
using Sav.Application.Attestations;
using Sav.Application.Verify;
using Sav.Domain.Analysis;
using Sav.Domain.Attestations;
using Sav.Infrastructure.Config;
using Sav.Infrastructure.Config.Policies;
using Sav.Infrastructure.Storage.Attestations;
using Xunit.Abstractions;

namespace Sav.Application.Tests.Verify;

public sealed class VerifyQueryHotPathMeasurementTests(ITestOutputHelper output)
{
    private const int WarmupRequests = 50;
    private const int RequestsPerTrial = 250;
    private const int TrialCount = 7;
    private static readonly byte[] Key = Enumerable.Repeat((byte)0x63, 32).ToArray();
    private readonly ITestOutputHelper _output = output;

    [Fact]
    public async Task Denied_policy_workload_reports_elapsed_time_and_loader_counts()
    {
        MeasurementSetup setup = CreateSetup();

        for (int request = 0; request < WarmupRequests; request++)
        {
            await setup.UseCase.ExecuteAsync(setup.Request, CancellationToken.None);
        }

        List<double> elapsedMilliseconds = [];
        for (int trial = 0; trial < TrialCount; trial++)
        {
            setup.ResetCounts();
            Stopwatch stopwatch = Stopwatch.StartNew();
            for (int request = 0; request < RequestsPerTrial; request++)
            {
                await setup.UseCase.ExecuteAsync(setup.Request, CancellationToken.None);
            }

            stopwatch.Stop();
            elapsedMilliseconds.Add(stopwatch.Elapsed.TotalMilliseconds);
        }

        double medianMilliseconds = elapsedMilliseconds.Order().ElementAt(TrialCount / 2);
        _output.WriteLine(
            "verify_query_denied median_ms={0:F3} policy_loads={1} contract_loads={2} requests={3}",
            medianMilliseconds,
            setup.PolicyLoader.LoadCount,
            setup.ContractLoader.LoadCount,
            RequestsPerTrial);

        Assert.True(medianMilliseconds > 0);
        Assert.Equal(RequestsPerTrial, setup.PolicyLoader.LoadCount);
        Assert.Equal(RequestsPerTrial, setup.ContractLoader.LoadCount);
    }

    [Fact]
    public async Task Verify_query_loads_policy_and_contract_once_per_request()
    {
        MeasurementSetup setup = CreateSetup();

        await setup.UseCase.ExecuteAsync(setup.Request, CancellationToken.None);

        Assert.Equal(1, setup.PolicyLoader.LoadCount);
        Assert.Equal(1, setup.ContractLoader.LoadCount);
    }

    private static MeasurementSetup CreateSetup()
    {
        string fixturesRoot = FixturePaths.ResolveRoot();
        FixturePathResolver paths = new(fixturesRoot);
        CountingPolicyLoader policyLoader = new(new YamlPolicyLoader());
        CountingContractLoader contractLoader = new(new YamlContractLoader());
        UnresolvedObjectParser parser = new();
        PipelineRecordingRedactor redactor = new();
        VerificationPipeline pipeline = new(
            parser,
            new YamlPolicyEngine(),
            policyLoader,
            contractLoader,
            paths,
            new FixedAliasResolver(),
            new RecordingSessionFactory(),
            new RecordingCatalog(),
            new RecordingPlanProvider(),
            new RecordingOracle(),
            new RecordingGuard(),
            redactor);
        VerifyQueryUseCase useCase = new(
            pipeline,
            parser,
            policyLoader,
            contractLoader,
            paths,
            new FixedAliasResolver(),
            new AttestationFactory(new AttestationHmac(), redactor),
            new InMemoryAttestationStore(),
            redactor,
            Key);

        return new MeasurementSetup(
            useCase,
            new VerifyQueryRequest(
                "SELECT id FROM t",
                "demo",
                "policies/valid-basic.yaml",
                "contracts/valid-basic.yaml"),
            policyLoader,
            contractLoader);
    }

    private sealed record MeasurementSetup(
        VerifyQueryUseCase UseCase,
        VerifyQueryRequest Request,
        CountingPolicyLoader PolicyLoader,
        CountingContractLoader ContractLoader)
    {
        public void ResetCounts()
        {
            PolicyLoader.Reset();
            ContractLoader.Reset();
        }
    }

    private sealed class FixturePathResolver(string fixturesRoot) : IConfigPathResolver
    {
        private readonly string _fixturesRoot = fixturesRoot ?? throw new ArgumentNullException(nameof(fixturesRoot));

        public string ResolveUnderConfigRoot(string relativeOrConfiguredPath) =>
            Path.Combine(
                _fixturesRoot,
                relativeOrConfiguredPath.Replace('/', Path.DirectorySeparatorChar));
    }

    private sealed class UnresolvedObjectParser : ISqlParser
    {
        public SqlParseResult Parse(string sql, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            SqlIr ir = new(
                "postgresql",
                ["Select"],
                ["t"],
                [],
                ["id"],
                [],
                [],
                false,
                false,
                ["t"],
                [],
                "SELECT id FROM t",
                "measurement-fingerprint");
            return new SqlParseResult(true, ir, null, null);
        }
    }

    private sealed class InMemoryAttestationStore : IAttestationStore
    {
        public Task<string> SaveAsync(Attestation attestation, CancellationToken cancellationToken) =>
            Task.FromResult(attestation.Id);

        public Task<Attestation?> GetAsync(string attestationId, CancellationToken cancellationToken) =>
            Task.FromResult<Attestation?>(null);
    }

    private static class FixturePaths
    {
        public static string ResolveRoot()
        {
            DirectoryInfo? current = new(AppContext.BaseDirectory);
            while (current is not null)
            {
                string candidate = Path.Combine(current.FullName, "tests", "fixtures");
                if (Directory.Exists(candidate))
                {
                    return candidate;
                }

                current = current.Parent;
            }

            throw new DirectoryNotFoundException("Could not locate tests/fixtures from the test output directory.");
        }
    }
}
