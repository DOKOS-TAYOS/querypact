namespace Sav.Domain.Errors;

/// <summary>
/// Closed set of machine codes allowed in <c>PropertyResult.RedactedDetail</c> when
/// <c>IncludeRowCounts=false</c> (strict attestation / oracle egress).
/// </summary>
public static class FixedPropertyDetailCodes
{
    private static readonly HashSet<string> Codes = new(StringComparer.Ordinal)
    {
        SavErrorCode.QueryFailed,
        SavErrorCode.UniqueViolation,
        SavErrorCode.NullFound,
        SavErrorCode.EmptyExpectedRows,
        SavErrorCode.UnsupportedConstruct,
        SavErrorCode.UnsafeIdentifier,
        SavErrorCode.SessionRequired,
        SavErrorCode.SessionReaderColumnForbidden,
        SavErrorCode.SessionReaderColumnsRequired,
        SavErrorCode.SchemaChanged,
        SavErrorCode.SchemaInvariantFailed,
        SavErrorCode.OrphansFound,
        SavErrorCode.NotEquivalent,
        SavErrorCode.AffectedRowsOutOfRange,
        SavErrorCode.PropertyEnvironmentForbidden,
        SavErrorCode.MvpAPropertiesRequired,
        SavErrorCode.PathNotAllowed,
        SavErrorCode.PolicyInvalid,
        SavErrorCode.ContractInvalid,
        SavErrorCode.AliasUnknown,
        SavErrorCode.AliasDsnMissing,
        SavErrorCode.AliasLooksLikeDsn,
        SavErrorCode.RoProbeMissing,
        SavErrorCode.RoleNotReadOnly,
        SavErrorCode.RoCanaryInconclusive,
        SavErrorCode.RoCanaryRollbackUnconfirmed,
        SavErrorCode.UnsafeWriteSuspected,
    };

    public static bool Contains(string? code) =>
        !string.IsNullOrEmpty(code) && Codes.Contains(code);

    /// <summary>
    /// Returns <paramref name="detail"/> when it is a known machine code; otherwise
    /// <see cref="SavErrorCode.QueryFailed"/>.
    /// </summary>
    public static string Coerce(string? detail) =>
        Contains(detail) ? detail! : SavErrorCode.QueryFailed;
}
