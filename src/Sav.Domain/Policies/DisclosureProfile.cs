namespace Sav.Domain.Policies;

/// <summary>
/// Disclosure flags for egress. Effective profile = intersection of contract and policy
/// (see <see cref="DisclosureProfileMerge"/>).
/// </summary>
public sealed record DisclosureProfile(
    string Name,
    bool IncludePlanSummary,
    bool IncludeObjectNames,
    bool IncludeTimings,
    bool IncludeRowCounts);
