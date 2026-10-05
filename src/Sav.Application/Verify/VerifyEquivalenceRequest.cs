namespace Sav.Application.Verify;

/// <summary>
/// verify_equivalence: two SELECT-only SQL texts compared via the closed
/// <c>query_equivalent</c> oracle property on the pipeline-opened RO session.
/// Paths resolved via <c>IConfigPathResolver</c>.
/// </summary>
public sealed record VerifyEquivalenceRequest(
    string LeftSql,
    string RightSql,
    string TargetAliasName,
    string PolicyPath,
    string ContractPath);
