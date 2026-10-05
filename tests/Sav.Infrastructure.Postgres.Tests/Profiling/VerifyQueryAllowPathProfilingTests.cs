using System.Diagnostics;
using Sav.Application.Abstractions;
using Sav.Application.Attestations;
using Sav.Application.Verify;
using Sav.Domain.Attestations;
using Sav.Domain.Contracts;
using Sav.Domain.Decisions;
using Sav.Domain.Policies;
using Sav.Domain.Targets;
using Sav.Infrastructure.Config;
using Sav.Infrastructure.Config.Policies;
using Sav.Infrastructure.Postgres.Catalog;
using Sav.Infrastructure.Postgres.Oracle;
using Sav.Infrastructure.Postgres.Parsing;
using Sav.Infrastructure.Postgres.Plans;
using Sav.Infrastructure.Postgres.Targets;
using Sav.Infrastructure.Postgres.Tests.Fixtures;
using Sav.Infrastructure.Storage.Attestations;
using Xunit.Abstractions;

namespace Sav.Infrastructure.Postgres.Tests.Profiling;

[Collection(nameof(PostgresRoCollection))]
public sealed class VerifyQueryAllowPathProfilingTests
{
    private const int WarmUpRequestCount = 10;
    private const int TrialCount = 5;
    private const int RequestsPerTrial = 20;
    private static readonly byte[] HmacKey = Enumerable.Repeat((byte)0x64, 32).ToArray();

    private readonly PostgresRoFixture _fixture;
    private readonly ITestOutputHelper _output;

    public VerifyQueryAllowPathProfilingTests(
        PostgresRoFixture fixture,
        ITestOutputHelper output)
    {
        _fixture = fixture;
        _output = output;
    }

    [Fact]
    public async Task Allow_path_reports_median_and_exact_final_stage_counts()
    {
        StageTimingCollector timings = new();
        VerifyQueryUseCase useCase = CreateUseCase(timings);

        for (int requestIndex = 0; requestIndex < WarmUpRequestCount; requestIndex++)
        {
            await AssertPassAsync(useCase, CreateRequest());
        }

        List<long> trialElapsedTicks = [];
        for (int trialIndex = 0; trialIndex < TrialCount; trialIndex++)
        {
            timings.Reset();
            long started = Stopwatch.GetTimestamp();
            for (int requestIndex = 0; requestIndex < RequestsPerTrial; requestIndex++)
            {
                await AssertPassAsync(useCase, CreateRequest());
            }

            trialElapsedTicks.Add(Stopwatch.GetTimestamp() - started);
        }

        Assert.Equal(RequestsPerTrial, timings.GetSnapshot("session_open").CallCount);
        Assert.Equal(RequestsPerTrial, timings.GetSnapshot("catalog_enrich").CallCount);
        Assert.Equal(RequestsPerTrial, timings.GetSnapshot("fingerprint_capture").CallCount);
        Assert.Equal(RequestsPerTrial * 2, timings.GetSnapshot("fingerprint_ensure").CallCount);
        Assert.Equal(RequestsPerTrial, timings.GetSnapshot("plan").CallCount);
        Assert.Equal(RequestsPerTrial, timings.GetSnapshot("property_oracle").CallCount);

        WriteMeasurements(trialElapsedTicks, timings);
    }

    private static async Task AssertPassAsync(VerifyQueryUseCase useCase, VerifyQueryRequest request)
    {
        VerifyQueryResponse response = await useCase.ExecuteAsync(request, CancellationToken.None);
        Assert.Equal(AttestationDecision.Pass, response.Attestation.Decision);
    }

    private static VerifyQueryRequest CreateRequest() => new(
        "SELECT id, payload FROM public.plan_items WHERE id = 1",
        PostgresRoFixture.RoAlias,
        "policies/security-deny-secrets.yaml",
        "contracts/valid-basic.yaml");

    private VerifyQueryUseCase CreateUseCase(StageTimingCollector timings)
    {
        LibPgQuerySqlParser parser = new();
        YamlPolicyLoader policyLoader = new();
        YamlContractLoader contractLoader = new();
        FixtureConfigPathResolver paths = new();
        TargetAliasResolver aliases = new(_fixture.Binding);
        VerificationPipeline pipeline = new(
            parser,
            new YamlPolicyEngine(),
            new UnusedPipelinePolicyLoader(),
            new UnusedPipelineContractLoader(),
            new UnusedPipelinePathResolver(),
            new UnusedPipelineAliasResolver(),
            new TimedReadOnlySessionFactory(_fixture.CreateFactory(), timings),
            new TimedCatalogResolver(new PgCatalogResolver(), timings),
            new TimedPlanProvider(new ExplainPlanProvider(_fixture.Redactor), timings),
            new TimedPropertyOracle(new PropertyOracle(_fixture.Redactor), timings),
            new TimedSchemaFingerprintGuard(new SchemaFingerprintGuard(), timings),
            _fixture.Redactor);

        return new VerifyQueryUseCase(
            pipeline,
            parser,
            policyLoader,
            contractLoader,
            paths,
            aliases,
            new AttestationFactory(new AttestationHmac(), _fixture.Redactor),
            new InMemoryAttestationStore(),
            _fixture.Redactor,
            HmacKey);
    }

    private void WriteMeasurements(List<long> trialElapsedTicks, StageTimingCollector timings)
    {
        double medianMilliseconds = trialElapsedTicks
            .Select(ToMilliseconds)
            .Order()
            .ElementAt(TrialCount / 2);
        _output.WriteLine("verify_query_allow median_ms={0:F3}", medianMilliseconds);

        foreach (string stage in new[]
                 {
                     "session_open",
                     "catalog_enrich",
                     "fingerprint_capture",
                     "fingerprint_ensure",
                     "plan",
                     "property_oracle",
                 })
        {
            StageTimingSnapshot snapshot = timings.GetSnapshot(stage);
            _output.WriteLine(
                "verify_query_allow stage={0} calls={1} elapsed_ms={2:F3}",
                stage,
                snapshot.CallCount,
                ToMilliseconds(snapshot.ElapsedTicks));
        }
    }

    private static double ToMilliseconds(long ticks) => ticks * 1_000d / Stopwatch.Frequency;

    private sealed class FixtureConfigPathResolver : IConfigPathResolver
    {
        private readonly string _fixtureRoot = FindFixtureRoot();

        public string ResolveUnderConfigRoot(string relativeOrConfiguredPath) =>
            Path.Combine(_fixtureRoot, relativeOrConfiguredPath.Replace('/', Path.DirectorySeparatorChar));

        private static string FindFixtureRoot()
        {
            DirectoryInfo? current = new(AppContext.BaseDirectory);
            while (current is not null)
            {
                if (File.Exists(Path.Combine(current.FullName, "QueryPact.sln")))
                {
                    return Path.Combine(current.FullName, "tests", "fixtures");
                }

                current = current.Parent;
            }

            throw new DirectoryNotFoundException(
                "Could not locate QueryPact.sln from the test output directory.");
        }
    }

    private sealed class InMemoryAttestationStore : IAttestationStore
    {
        public Task<string> SaveAsync(Attestation attestation, CancellationToken cancellationToken) =>
            Task.FromResult(attestation.Id);

        public Task<Attestation?> GetAsync(string attestationId, CancellationToken cancellationToken) =>
            Task.FromResult<Attestation?>(null);
    }

    private sealed class UnusedPipelinePolicyLoader : IPolicyLoader
    {
        public Task<Policy> LoadAsync(string path, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("The verification pipeline context overload must be used.");
    }

    private sealed class UnusedPipelineContractLoader : IContractLoader
    {
        public Task<Contract> LoadAsync(string path, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("The verification pipeline context overload must be used.");
    }

    private sealed class UnusedPipelinePathResolver : IConfigPathResolver
    {
        public string ResolveUnderConfigRoot(string relativeOrConfiguredPath) =>
            throw new InvalidOperationException("The verification pipeline context overload must be used.");
    }

    private sealed class UnusedPipelineAliasResolver : ITargetAliasResolver
    {
        public TargetAlias Resolve(string aliasName) =>
            throw new InvalidOperationException("The verification pipeline context overload must be used.");
    }
}
