using Sav.Domain.Analysis;

namespace Sav.Application.Analyze;

internal static class SqlIrFactory
{
    public static SqlIr CreateUnparsable() =>
        new(
            dialect: "postgresql",
            statementTypes: [],
            tablesRead: [],
            tablesWritten: [],
            columnsRead: [],
            columnsWritten: [],
            functions: [],
            hasMultipleStatements: false,
            hasDynamicSql: false,
            unresolvedObjects: [],
            riskCodes: ["sql_unparsable"],
            normalizedSql: string.Empty,
            fingerprint: string.Empty);
}
