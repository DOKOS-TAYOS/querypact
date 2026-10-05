namespace Sav.Domain.Attestations;

public sealed record StructuralSqlIr
{
    public StructuralSqlIr(
        string dialect,
        IReadOnlyList<string> statementTypes,
        IReadOnlyList<string> tablesRead,
        IReadOnlyList<string> tablesWritten,
        IReadOnlyList<string> columnsRead,
        IReadOnlyList<string> columnsWritten,
        IReadOnlyList<string> functions,
        bool hasMultipleStatements,
        bool hasDynamicSql,
        IReadOnlyList<string> unresolvedObjects,
        IReadOnlyList<string> riskCodes)
    {
        ArgumentNullException.ThrowIfNull(statementTypes);
        ArgumentNullException.ThrowIfNull(tablesRead);
        ArgumentNullException.ThrowIfNull(tablesWritten);
        ArgumentNullException.ThrowIfNull(columnsRead);
        ArgumentNullException.ThrowIfNull(columnsWritten);
        ArgumentNullException.ThrowIfNull(functions);
        ArgumentNullException.ThrowIfNull(unresolvedObjects);
        ArgumentNullException.ThrowIfNull(riskCodes);

        Dialect = dialect;
        StatementTypes = statementTypes.ToArray();
        TablesRead = tablesRead.ToArray();
        TablesWritten = tablesWritten.ToArray();
        ColumnsRead = columnsRead.ToArray();
        ColumnsWritten = columnsWritten.ToArray();
        Functions = functions.ToArray();
        HasMultipleStatements = hasMultipleStatements;
        HasDynamicSql = hasDynamicSql;
        UnresolvedObjects = unresolvedObjects.ToArray();
        RiskCodes = riskCodes.ToArray();
    }

    public string Dialect { get; }

    public IReadOnlyList<string> StatementTypes { get; }

    public IReadOnlyList<string> TablesRead { get; }

    public IReadOnlyList<string> TablesWritten { get; }

    public IReadOnlyList<string> ColumnsRead { get; }

    public IReadOnlyList<string> ColumnsWritten { get; }

    public IReadOnlyList<string> Functions { get; }

    public bool HasMultipleStatements { get; }

    public bool HasDynamicSql { get; }

    public IReadOnlyList<string> UnresolvedObjects { get; }

    public IReadOnlyList<string> RiskCodes { get; }
}
