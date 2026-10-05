using Sav.Domain.Analysis;
using Sav.Domain.Attestations;

namespace Sav.Application.Analyze;

public static class SqlIrToStructuralMapper
{
    private static StructuralSqlIr ToStructural(SqlIr ir)
    {
        ArgumentNullException.ThrowIfNull(ir);
        return new StructuralSqlIr(
            dialect: ir.Dialect,
            statementTypes: ir.StatementTypes,
            tablesRead: ir.TablesRead,
            tablesWritten: ir.TablesWritten,
            columnsRead: ir.ColumnsRead,
            columnsWritten: ir.ColumnsWritten,
            functions: ir.Functions,
            hasMultipleStatements: ir.HasMultipleStatements,
            hasDynamicSql: ir.HasDynamicSql,
            unresolvedObjects: ir.UnresolvedObjects,
            riskCodes: ir.RiskCodes);
    }

    public static AttestationAnalysis ToAttestationAnalysis(SqlAnalysis analysis)
    {
        ArgumentNullException.ThrowIfNull(analysis);
        return new AttestationAnalysis(
            Ir: ToStructural(analysis.Ir),
            IsParsable: analysis.IsParsable);
    }
}
