using Sav.Domain.Errors;
using Sav.Domain.Policies;

namespace Sav.Infrastructure.Config.Internal;

internal sealed class DisclosureYamlDocument
{
    public string? Name { get; set; }

    public bool? IncludePlanSummary { get; set; }

    public bool? IncludeObjectNames { get; set; }

    public bool? IncludeTimings { get; set; }

    public bool? IncludeRowCounts { get; set; }
}

internal static class YamlDisclosureMapper
{
    public static DisclosureProfile Map(DisclosureYamlDocument? document, string errorCode)
    {
        if (document is null)
        {
            throw new SavException(errorCode, $"{errorCode}: disclosure is required.");
        }

        if (string.IsNullOrWhiteSpace(document.Name)
            || document.IncludePlanSummary is null
            || document.IncludeObjectNames is null
            || document.IncludeTimings is null
            || document.IncludeRowCounts is null)
        {
            throw new SavException(errorCode, $"{errorCode}: disclosure fields are incomplete.");
        }

        return new DisclosureProfile(
            Name: document.Name,
            IncludePlanSummary: document.IncludePlanSummary.Value,
            IncludeObjectNames: document.IncludeObjectNames.Value,
            IncludeTimings: document.IncludeTimings.Value,
            IncludeRowCounts: document.IncludeRowCounts.Value);
    }
}
