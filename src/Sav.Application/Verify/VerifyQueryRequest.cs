namespace Sav.Application.Verify;

/// <summary>
/// Exactly one SQL text for verify_query. Paths resolved via <c>IConfigPathResolver</c>.
/// </summary>
public sealed record VerifyQueryRequest(
    string Sql,
    string TargetAliasName,
    string PolicyPath,
    string ContractPath);
