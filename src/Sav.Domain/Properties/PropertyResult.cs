using Sav.Domain.Decisions;

namespace Sav.Domain.Properties;

public sealed record PropertyResult(
    string Name,
    PropertyStatus Status,
    string? RedactedDetail);
