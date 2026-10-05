using Sav.Domain.Policies;

namespace Sav.Domain.Tests;

public sealed class DisclosureProfileMergeTests
{
    [Fact]
    public void StrictDefaults_closes_all_disclosure_flags()
    {
        DisclosureProfile defaults = DisclosureProfileMerge.StrictDefaults();

        Assert.False(defaults.IncludePlanSummary);
        Assert.False(defaults.IncludeObjectNames);
        Assert.False(defaults.IncludeTimings);
        Assert.False(defaults.IncludeRowCounts);
    }

    [Fact]
    public void Intersect_requires_both_true_for_each_flag()
    {
        DisclosureProfile open = new(
            Name: "open",
            IncludePlanSummary: true,
            IncludeObjectNames: true,
            IncludeTimings: true,
            IncludeRowCounts: true);
        DisclosureProfile partial = new(
            Name: "partial",
            IncludePlanSummary: true,
            IncludeObjectNames: false,
            IncludeTimings: true,
            IncludeRowCounts: false);

        DisclosureProfile effective = DisclosureProfileMerge.Intersect(open, partial);

        Assert.True(effective.IncludePlanSummary);
        Assert.False(effective.IncludeObjectNames);
        Assert.True(effective.IncludeTimings);
        Assert.False(effective.IncludeRowCounts);
    }

    [Fact]
    public void Missing_contract_intersects_policy_with_strict_defaults()
    {
        DisclosureProfile policy = new(
            Name: "policy",
            IncludePlanSummary: true,
            IncludeObjectNames: true,
            IncludeTimings: true,
            IncludeRowCounts: true);

        DisclosureProfile effective = DisclosureProfileMerge.Intersect(
            policy,
            DisclosureProfileMerge.StrictDefaults());

        Assert.False(effective.IncludePlanSummary);
        Assert.False(effective.IncludeObjectNames);
        Assert.False(effective.IncludeTimings);
        Assert.False(effective.IncludeRowCounts);
    }

    [Fact]
    public void Intersect_is_commutative_for_flags()
    {
        DisclosureProfile left = new("left", true, false, true, false);
        DisclosureProfile right = new("right", true, true, false, false);

        DisclosureProfile ab = DisclosureProfileMerge.Intersect(left, right);
        DisclosureProfile ba = DisclosureProfileMerge.Intersect(right, left);

        Assert.Equal(ab.IncludePlanSummary, ba.IncludePlanSummary);
        Assert.Equal(ab.IncludeObjectNames, ba.IncludeObjectNames);
        Assert.Equal(ab.IncludeTimings, ba.IncludeTimings);
        Assert.Equal(ab.IncludeRowCounts, ba.IncludeRowCounts);
    }
}
