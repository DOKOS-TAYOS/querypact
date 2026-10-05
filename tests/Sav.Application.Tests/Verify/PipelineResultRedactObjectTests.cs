using Sav.Application.Abstractions;
using Sav.Application.Verify;
using Sav.Domain.Decisions;
using Sav.Domain.Plans;
using Sav.Domain.Policies;
using Sav.Domain.Properties;

namespace Sav.Application.Tests.Verify;

public sealed class PipelineResultRedactObjectTests
{
    private const string Canary = "CANARY_LITERAL_do_not_egress@example.invalid";

    [Fact]
    public async Task Allow_path_always_calls_RedactObject_once()
    {
        PipelineRecordingRedactor redactor = new();
        VerificationPipeline pipeline = CreateAllowPipeline(
            new RecordingOracle(),
            redactor);

        _ = await pipeline.ExecuteAsync(
            new VerifyQueryRequest("SELECT 1", "demo", "p.yaml", "c.yaml"),
            CancellationToken.None);

        Assert.Equal(1, redactor.RedactObjectCalls);
    }

    [Fact]
    public async Task Pipeline_result_passes_through_redactor_before_return()
    {
        CanaryScrubbingPipelineRedactor redactor = new(Canary);
        RecordingOracle oracle = new(_ =>
        [
            new PropertyResult("query_succeeds", PropertyStatus.Pass, Canary),
            new PropertyResult("empty_result", PropertyStatus.Pass, null),
        ]);

        VerificationPipeline pipeline = CreateAllowPipeline(oracle, redactor);

        VerificationPipelineResult result = await pipeline.ExecuteAsync(
            new VerifyQueryRequest("SELECT 1", "demo", "p.yaml", "c.yaml"),
            CancellationToken.None);

        Assert.Equal(AttestationDecision.Pass, result.Decision);
        Assert.Equal(1, redactor.RedactObjectCalls);
        Assert.DoesNotContain(Canary, result.Properties[0].RedactedDetail ?? string.Empty, StringComparison.Ordinal);
    }

    private static VerificationPipeline CreateAllowPipeline(
        IPropertyOracle oracle,
        IRedactor redactor) =>
        new(
            new FixedParser(success: true),
            new ScriptedPolicyEngine(
                new PolicyDecision(PolicyOutcome.Allow, [], []),
                new PolicyDecision(PolicyOutcome.Allow, [], [])),
            new FixedPolicyLoader(),
            new FixedContractLoader(),
            new FixedPathResolver(),
            new FixedAliasResolver(),
            new RecordingSessionFactory(),
            new RecordingCatalog(),
            new RecordingPlanProvider(PlanGateOutcome.Allow),
            oracle,
            new RecordingGuard(),
            redactor);

    private sealed class CanaryScrubbingPipelineRedactor : IRedactor
    {
        private readonly string _canary;

        public CanaryScrubbingPipelineRedactor(string canary)
        {
            _canary = canary;
        }

        public int RedactObjectCalls { get; private set; }

        public string RedactText(string value, DisclosureProfile profile) =>
            value.Replace(_canary, "[REDACTED]", StringComparison.Ordinal);

        public T RedactObject<T>(T value, DisclosureProfile profile)
        {
            RedactObjectCalls++;
            if (value is VerificationPipelineResult pipeline)
            {
                PropertyResult[] props = pipeline.Properties
                    .Select(p => new PropertyResult(
                        p.Name,
                        p.Status,
                        p.RedactedDetail is null
                            ? null
                            : RedactText(p.RedactedDetail, profile)))
                    .ToArray();

                VerificationPipelineResult scrubbed = pipeline with { Properties = props };
                return (T)(object)scrubbed;
            }

            return value;
        }
    }
}
