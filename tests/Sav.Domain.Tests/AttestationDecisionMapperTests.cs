using Sav.Domain.Decisions;
using Sav.Domain.Plans;

namespace Sav.Domain.Tests;

public sealed class AttestationDecisionMapperTests
{
    [Theory]
    [InlineData(false, PolicyOutcome.Allow, null, AttestationDecision.Deny)]
    [InlineData(true, PolicyOutcome.Deny, null, AttestationDecision.Deny)]
    [InlineData(true, PolicyOutcome.Review, null, AttestationDecision.Review)]
    public void Maps_policy_and_parsability_short_circuits(
        bool isParsable,
        PolicyOutcome policy,
        PlanGateOutcome? plan,
        AttestationDecision expected)
    {
        AttestationDecision actual = AttestationDecisionMapper.Map(
            isParsable,
            policy,
            plan,
            requiredPropertyStatuses: null);

        Assert.Equal(expected, actual);
    }

    [Theory]
    [InlineData(PlanGateOutcome.Deny, AttestationDecision.Deny)]
    [InlineData(PlanGateOutcome.Review, AttestationDecision.Review)]
    public void Maps_plan_gate_deny_and_review_after_policy_allow(
        PlanGateOutcome plan,
        AttestationDecision expected)
    {
        AttestationDecision actual = AttestationDecisionMapper.Map(
            isParsable: true,
            PolicyOutcome.Allow,
            plan,
            requiredPropertyStatuses: [PropertyStatus.Pass]);

        Assert.Equal(expected, actual);
    }

    [Fact]
    public void Maps_required_property_fail_or_error_to_fail()
    {
        Assert.Equal(
            AttestationDecision.Fail,
            AttestationDecisionMapper.Map(
                true,
                PolicyOutcome.Allow,
                PlanGateOutcome.Allow,
                [PropertyStatus.Fail]));

        Assert.Equal(
            AttestationDecision.Fail,
            AttestationDecisionMapper.Map(
                true,
                PolicyOutcome.Allow,
                PlanGateOutcome.Allow,
                [PropertyStatus.Error]));
    }

    [Fact]
    public void Maps_required_property_not_evaluated_to_review()
    {
        AttestationDecision actual = AttestationDecisionMapper.Map(
            true,
            PolicyOutcome.Allow,
            PlanGateOutcome.Allow,
            [PropertyStatus.NotEvaluated]);

        Assert.Equal(AttestationDecision.Review, actual);
    }

    [Fact]
    public void Maps_empty_required_property_statuses_to_review()
    {
        AttestationDecision actual = AttestationDecisionMapper.Map(
            isParsable: true,
            PolicyOutcome.Allow,
            PlanGateOutcome.Allow,
            requiredPropertyStatuses: []);

        Assert.Equal(AttestationDecision.Review, actual);
    }

    [Fact]
    public void Maps_all_allow_and_pass_to_pass()
    {
        AttestationDecision actual = AttestationDecisionMapper.Map(
            true,
            PolicyOutcome.Allow,
            PlanGateOutcome.Allow,
            [PropertyStatus.Pass, PropertyStatus.Pass]);

        Assert.Equal(AttestationDecision.Pass, actual);
    }

    [Fact]
    public void Vocabulary_enums_expose_closed_sets()
    {
        Assert.Equal(
            ["Allow", "Deny", "Review"],
            Enum.GetNames<PolicyOutcome>());
        Assert.Equal(
            ["Allow", "Deny", "Review"],
            Enum.GetNames<PlanGateOutcome>());
        Assert.Equal(
            ["Pass", "Fail", "Error", "NotEvaluated"],
            Enum.GetNames<PropertyStatus>());
        Assert.Equal(
            ["Pass", "Fail", "Review", "Deny"],
            Enum.GetNames<AttestationDecision>());
    }
}
