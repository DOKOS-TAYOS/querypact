using Sav.Domain.Attestations;
using Sav.Domain.Decisions;
using Sav.Domain.Plans;
using Sav.Domain.Policies;
using Sav.Domain.Properties;

namespace Sav.Application.Attestations;

/// <summary>
/// Unsigned attestation draft. Hashes are precomputed by the caller; factory redacts then signs.
/// </summary>
public sealed record AttestationDraft(
    string SchemaVersion,
    string Id,
    string SqlHash,
    string ContractHash,
    string PolicyHash,
    string SavVersion,
    string TargetAliasFingerprint,
    AttestationDecision Decision,
    AttestationAnalysis Analysis,
    PlanSummary? PlanSummary,
    IReadOnlyList<PropertyResult> Properties,
    DisclosureProfile EffectiveDisclosure,
    DateTimeOffset Timestamp);
