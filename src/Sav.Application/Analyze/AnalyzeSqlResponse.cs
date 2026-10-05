using Sav.Domain.Attestations;
using Sav.Domain.Decisions;
using Sav.Domain.Policies;

namespace Sav.Application.Analyze;

public sealed record AnalyzeSqlResponse(
    PolicyDecision Decision,
    AttestationAnalysis Analysis,
    IReadOnlyList<string> RedactedReasons,
    DisclosureProfile EffectiveDisclosure);
