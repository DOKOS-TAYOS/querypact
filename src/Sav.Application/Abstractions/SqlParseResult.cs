using Sav.Domain.Analysis;

namespace Sav.Application.Abstractions;

public sealed record SqlParseResult(
    bool Success,
    SqlIr? Ir,
    string? ErrorCode,
    string? RedactedMessage);
