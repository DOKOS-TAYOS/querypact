using Sav.Domain.Attestations;
using Sav.Domain.Decisions;
using Sav.Domain.Errors;

namespace Sav.Application.Verify;

internal static class VerificationAttestationHelpers
{
    public static AttestationDecision MapSavExceptionDecision(string code) =>
        code switch
        {
            SavErrorCode.SchemaChanged => AttestationDecision.Review,
            SavErrorCode.QueryFailed
                or SavErrorCode.UniqueViolation
                or SavErrorCode.NullFound
                or SavErrorCode.EmptyExpectedRows
                or SavErrorCode.SchemaInvariantFailed
                or SavErrorCode.OrphansFound
                or SavErrorCode.NotEquivalent
                or SavErrorCode.AffectedRowsOutOfRange => AttestationDecision.Fail,
            _ => AttestationDecision.Deny,
        };

    public static AttestationAnalysis WithSchemaChangedRisk(AttestationAnalysis analysis)
    {
        StructuralSqlIr ir = analysis.Ir;
        if (ir.RiskCodes.Contains(SavErrorCode.SchemaChanged, StringComparer.Ordinal))
        {
            return analysis;
        }

        string[] riskCodes = ir.RiskCodes.Append(SavErrorCode.SchemaChanged).ToArray();
        StructuralSqlIr updated = new(
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
            riskCodes: riskCodes);

        return new AttestationAnalysis(updated, analysis.IsParsable);
    }
}
