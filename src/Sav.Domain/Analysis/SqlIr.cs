namespace Sav.Domain.Analysis;

public sealed record SqlIr
{
    // Preserve the existing public constructor, including its optional parameters.
    public SqlIr(
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
        IReadOnlyList<string> riskCodes,
        string normalizedSql,
        string fingerprint,
        IReadOnlyList<string>? operators = null,
        IReadOnlyList<string>? functionReferences = null)
        : this(dialect, statementTypes, tablesRead, tablesWritten, columnsRead, columnsWritten,
            functions, hasMultipleStatements, hasDynamicSql, unresolvedObjects, riskCodes,
            normalizedSql, fingerprint, operators, functionReferences, null)
    {
    }

    public SqlIr(
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
        IReadOnlyList<string> riskCodes,
        string normalizedSql,
        string fingerprint,
        IReadOnlyList<string>? operators,
        IReadOnlyList<string>? functionReferences,
        IReadOnlyList<string>? typeReferences)
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
        FunctionReferences = functionReferences?.ToArray() ?? Functions.ToArray();
        Operators = operators?.ToArray() ?? [];
        TypeReferences = typeReferences?.ToArray() ?? [];
        HasMultipleStatements = hasMultipleStatements;
        HasDynamicSql = hasDynamicSql;
        UnresolvedObjects = unresolvedObjects.ToArray();
        RiskCodes = riskCodes.ToArray();
        NormalizedSql = normalizedSql;
        Fingerprint = fingerprint;
    }

    public string Dialect { get; }

    public IReadOnlyList<string> StatementTypes { get; }

    public IReadOnlyList<string> TablesRead { get; }

    public IReadOnlyList<string> TablesWritten { get; }

    public IReadOnlyList<string> ColumnsRead { get; }

    public IReadOnlyList<string> ColumnsWritten { get; }

    public IReadOnlyList<string> Functions { get; }

    /// <summary>
    /// Internal lexical PostgreSQL function references retained for live catalog safety validation.
    /// Explicit schema qualification is preserved here even when <see cref="Functions"/> is canonicalized.
    /// This field is intentionally omitted from external structural attestations.
    /// </summary>
    public IReadOnlyList<string> FunctionReferences { get; }

    /// <summary>
    /// Internal PostgreSQL operator names retained for live catalog safety validation.
    /// This field is intentionally omitted from external structural attestations.
    /// </summary>
    public IReadOnlyList<string> Operators { get; }

    /// <summary>
    /// Internal PostgreSQL type names, including array suffixes, retained for conversion safety.
    /// Omitted from external structural attestations.
    /// </summary>
    public IReadOnlyList<string> TypeReferences { get; }

    /// <summary>
    /// Parser-proven simple SELECT of int4 literals only; zero means no proof.
    /// Internal conversion evidence, omitted from external structural attestations.
    /// </summary>
    public int Int4ConstantProjectionCount { get; init; }

    public bool HasMultipleStatements { get; }

    public bool HasDynamicSql { get; }

    public IReadOnlyList<string> UnresolvedObjects { get; }

    public IReadOnlyList<string> RiskCodes { get; }

    public string NormalizedSql { get; }

    public string Fingerprint { get; }
}
