using Sav.Domain.Analysis;

namespace Sav.Security.Tests;

internal static class OracleTestIr
{
    public static SqlIr Create(
        string[]? statementTypes = null,
        string[]? tablesRead = null,
        string[]? tablesWritten = null,
        string[]? columnsRead = null,
        string[]? functions = null,
        bool hasMultipleStatements = false,
        bool hasDynamicSql = false,
        string agentSql = "SELECT 1")
    {
        return new SqlIr(
            dialect: "postgresql",
            statementTypes: statementTypes ?? ["Select"],
            tablesRead: tablesRead ?? [],
            tablesWritten: tablesWritten ?? [],
            columnsRead: columnsRead ?? [],
            columnsWritten: [],
            functions: functions ?? [],
            hasMultipleStatements: hasMultipleStatements,
            hasDynamicSql: hasDynamicSql,
            unresolvedObjects: [],
            riskCodes: [],
            normalizedSql: agentSql,
            fingerprint: "test-fp");
    }
}
