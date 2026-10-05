using Sav.Domain.Contracts;
using Sav.Domain.Policies;
using Sav.Domain.Targets;

namespace Sav.Application.Verify;

/// <summary>
/// Configuration resolved once by the caller and consumed by a verification pipeline run.
/// </summary>
public sealed record VerificationPipelineContext(
    TargetAlias Target,
    Policy Policy,
    Contract Contract,
    DisclosureProfile EffectiveDisclosure,
    DateTimeOffset PipelineStartedUtc);
