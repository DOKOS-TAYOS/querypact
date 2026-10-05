using Sav.Domain.Plans;

namespace Sav.Domain.Decisions;

public static class AttestationDecisionMapper
{
    public static string ToWire(AttestationDecision decision) =>
        decision switch
        {
            AttestationDecision.Pass => "PASS",
            AttestationDecision.Fail => "FAIL",
            AttestationDecision.Review => "REVIEW",
            AttestationDecision.Deny => "DENY",
            _ => throw new ArgumentOutOfRangeException(nameof(decision), decision, "Unknown attestation decision."),
        };

    public static AttestationDecision Map(
        bool isParsable,
        PolicyOutcome policyOutcome,
        PlanGateOutcome? planGateOutcome,
        IReadOnlyList<PropertyStatus>? requiredPropertyStatuses)
    {
        if (!isParsable || policyOutcome == PolicyOutcome.Deny)
        {
            return AttestationDecision.Deny;
        }

        if (policyOutcome == PolicyOutcome.Review)
        {
            return AttestationDecision.Review;
        }

        if (planGateOutcome == PlanGateOutcome.Deny)
        {
            return AttestationDecision.Deny;
        }

        if (planGateOutcome == PlanGateOutcome.Review)
        {
            return AttestationDecision.Review;
        }

        if (requiredPropertyStatuses is not null)
        {
            if (requiredPropertyStatuses.Count == 0)
            {
                // Fail closed: empty MVP-A property set must never yield PASS.
                return AttestationDecision.Review;
            }

            foreach (PropertyStatus status in requiredPropertyStatuses)
            {
                if (status is PropertyStatus.Fail or PropertyStatus.Error)
                {
                    return AttestationDecision.Fail;
                }
            }

            foreach (PropertyStatus status in requiredPropertyStatuses)
            {
                if (status == PropertyStatus.NotEvaluated)
                {
                    return AttestationDecision.Review;
                }
            }
        }

        if (policyOutcome == PolicyOutcome.Allow &&
            (planGateOutcome is null or PlanGateOutcome.Allow))
        {
            return AttestationDecision.Pass;
        }

        return AttestationDecision.Review;
    }
}
