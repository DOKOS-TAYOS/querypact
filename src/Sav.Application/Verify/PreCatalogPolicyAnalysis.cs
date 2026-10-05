using Sav.Domain.Analysis;

namespace Sav.Application.Verify;

internal static class PreCatalogPolicyAnalysis
{
    public static SqlAnalysis Create(SqlAnalysis analysis)
    {
        ArgumentNullException.ThrowIfNull(analysis);

        if (!analysis.IsParsable || analysis.Ir.UnresolvedObjects.Count == 0)
        {
            return analysis;
        }

        SqlIr ir = analysis.Ir;
        SqlIr preCatalogIr = new(
            ir.Dialect,
            ir.StatementTypes,
            ir.TablesRead,
            ir.TablesWritten,
            ir.ColumnsRead,
            ir.ColumnsWritten,
            ir.Functions,
            ir.HasMultipleStatements,
            ir.HasDynamicSql,
            unresolvedObjects: [],
            ir.RiskCodes,
            ir.NormalizedSql,
            ir.Fingerprint,
            ir.Operators,
            ir.FunctionReferences,
            ir.TypeReferences);

        return new SqlAnalysis(preCatalogIr, analysis.IsParsable);
    }
}
