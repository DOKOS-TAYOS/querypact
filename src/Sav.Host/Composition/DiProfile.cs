namespace Sav.Host.Composition;

/// <summary>
/// Host DI profile selected by <c>Sav:Mode</c> / <c>SAV_MODE</c>.
/// </summary>
public enum DiProfile
{
    /// <summary>Analyze + version/help + MCP analyze_sql only. No HMAC.</summary>
    AnalyzeOnly = 0,

    /// <summary>Full CLI/MCP surface. Requires attestation HMAC key.</summary>
    Full = 1,
}
