using Sav.Application.Abstractions;
using Sav.Domain.Decisions;
using Sav.Domain.Plans;
using Sav.Domain.Policies;
using Sav.Domain.Targets;
using Sav.Infrastructure.Postgres.Plans;
using Sav.Infrastructure.Postgres.Redaction;

namespace Sav.Infrastructure.Postgres.Tests.Plans;

public sealed class NoExplainOnDenyOrReviewTests
{
    private sealed class CountingSession : IReadOnlySession
    {
        public int ExecuteCount { get; private set; }

        public int ReaderCount { get; private set; }

        public Task ExecuteAsync(string sql, CancellationToken cancellationToken)
        {
            ExecuteCount++;
            return Task.CompletedTask;
        }

        public Task<IReadOnlyList<OracleScalarRow>> ExecuteReaderAsync(
            string sql,
            IReadOnlyList<OracleScalarColumn> allowedColumns,
            CancellationToken cancellationToken)
        {
            ReaderCount++;
            return Task.FromResult<IReadOnlyList<OracleScalarRow>>([]);
        }

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    [Theory]
    [InlineData(PolicyOutcome.Deny, PlanGateOutcome.Deny)]
    [InlineData(PolicyOutcome.Review, PlanGateOutcome.Review)]
    public async Task Deny_or_review_skips_explain_and_session_io(
        PolicyOutcome policyOutcome,
        PlanGateOutcome expected)
    {
        CountingSession session = new();
        ExplainPlanProvider provider = new(new MinimalStrictRedactor());
        Policy policy = new(
            "p",
            "1",
            ["Select"],
            [],
            [],
            [],
            true,
            true,
            true,
            "high",
            [],
            new DisclosureProfile("strict", false, false, false, false));

        PlanGateResult result = await provider.GetEstimatedPlanAsync(
            new TargetAlias("a", "fp"),
            "SELECT 1",
            new PolicyDecision(policyOutcome, ["policy_reason"], ["r1"]),
            policy,
            session,
            CancellationToken.None);

        Assert.Equal(expected, result.Outcome);
        Assert.Null(result.Summary);
        Assert.Equal(0, session.ExecuteCount);
        Assert.Equal(0, session.ReaderCount);

        PlanGateResult withNullSession = await provider.GetEstimatedPlanAsync(
            new TargetAlias("a", "fp"),
            "SELECT 1",
            new PolicyDecision(policyOutcome, ["policy_reason"], ["r1"]),
            policy,
            session: null,
            CancellationToken.None);
        Assert.Equal(expected, withNullSession.Outcome);
        Assert.Null(withNullSession.Summary);
    }
}
