namespace Sav.Domain.Policies;

public static class DisclosureProfileMerge
{
    public static DisclosureProfile StrictDefaults(string name = "strict")
    {
        return new DisclosureProfile(
            Name: name,
            IncludePlanSummary: false,
            IncludeObjectNames: false,
            IncludeTimings: false,
            IncludeRowCounts: false);
    }

    public static DisclosureProfile Intersect(DisclosureProfile left, DisclosureProfile right)
    {
        ArgumentNullException.ThrowIfNull(left);
        ArgumentNullException.ThrowIfNull(right);

        return new DisclosureProfile(
            Name: $"intersect({left.Name},{right.Name})",
            IncludePlanSummary: left.IncludePlanSummary && right.IncludePlanSummary,
            IncludeObjectNames: left.IncludeObjectNames && right.IncludeObjectNames,
            IncludeTimings: left.IncludeTimings && right.IncludeTimings,
            IncludeRowCounts: left.IncludeRowCounts && right.IncludeRowCounts);
    }
}
