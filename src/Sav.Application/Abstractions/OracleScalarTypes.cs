namespace Sav.Application.Abstractions;

public enum OracleScalarKind
{
    BoolV,
    LongV,
    StringV,
}

public sealed record OracleScalarColumn(string Name, OracleScalarKind Kind);

public sealed record OracleScalarRow(
    bool? BoolV,
    long? LongV,
    string? StringV);
