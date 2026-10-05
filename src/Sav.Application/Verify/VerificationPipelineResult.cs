using Sav.Domain.Attestations;
using Sav.Domain.Decisions;
using Sav.Domain.Plans;
using Sav.Domain.Policies;
using Sav.Domain.Properties;

namespace Sav.Application.Verify;

/// <summary>
/// Internal verify pipeline DTO: no AttestationId, no HMAC, no store interaction.
/// </summary>
public sealed record VerificationPipelineResult(
    AttestationDecision Decision,
    AttestationAnalysis Analysis,
    PlanSummary? PlanSummary,
    IReadOnlyList<PropertyResult> Properties,
    DisclosureProfile EffectiveDisclosure,
    IReadOnlyList<string> RedactedReasons);
