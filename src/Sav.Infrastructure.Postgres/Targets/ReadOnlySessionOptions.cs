using Sav.Domain.Policies;

namespace Sav.Infrastructure.Postgres.Targets;

public sealed class ReadOnlySessionOptions
{
    public TimeSpan StatementTimeout { get; init; } = TimeSpan.FromSeconds(5);

    public TimeSpan LockTimeout { get; init; } = TimeSpan.FromSeconds(2);

    public DisclosureProfile Disclosure { get; init; } = new(
        "strict",
        IncludePlanSummary: false,
        IncludeObjectNames: false,
        IncludeTimings: false,
        IncludeRowCounts: false);
}
