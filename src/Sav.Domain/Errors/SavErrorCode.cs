namespace Sav.Domain.Errors;

/// <summary>
/// Closed machine codes for typed Domain/Application failures (fail-closed egress).
/// </summary>
public static class SavErrorCode
{
    public const string PathNotAllowed = "path_not_allowed";
    public const string PolicyInvalid = "policy_invalid";
    public const string ContractInvalid = "contract_invalid";
    public const string AttestationIdInvalid = "attestation_id_invalid";
    public const string AttestationHmacKeyMissing = "attestation_hmac_key_missing";
    public const string AttestationHmacKeyInvalidEncoding = "attestation_hmac_key_invalid_encoding";
    public const string AttestationHmacKeyTooWeak = "attestation_hmac_key_too_weak";
    public const string AttestationIntegrityFailure = "attestation_integrity_failure";
    public const string SchemaChanged = "schema_changed";
    public const string QueryFailed = "query_failed";
    public const string UniqueViolation = "unique_violation";
    public const string NullFound = "null_found";
    public const string EmptyExpectedRows = "empty_expected_rows";
    public const string UnsupportedConstruct = "unsupported_construct";
    public const string AliasUnknown = "alias_unknown";
    public const string AliasDsnMissing = "alias_dsn_missing";
    public const string AliasLooksLikeDsn = "alias_looks_like_dsn";
    public const string RoProbeMissing = "ro_probe_missing";
    public const string RoleNotReadOnly = "role_not_read_only";
    public const string RoCanaryInconclusive = "ro_canary_inconclusive";
    public const string RoCanaryRollbackUnconfirmed = "ro_canary_rollback_unconfirmed";
    public const string SessionReaderColumnsRequired = "session_reader_columns_required";
    public const string SessionReaderColumnForbidden = "session_reader_column_forbidden";
    public const string SessionRequired = "session_required";
    public const string UnsafeWriteSuspected = "unsafe_write_suspected";
    public const string UnsafeIdentifier = "unsafe_identifier";
    public const string PropertyEnvironmentForbidden = "property_environment_forbidden";
    public const string NotEquivalent = "not_equivalent";
    public const string AffectedRowsOutOfRange = "affected_rows_out_of_range";
    public const string SchemaInvariantFailed = "schema_invariant_failed";
    public const string OrphansFound = "orphans_found";
    public const string MvpAPropertiesRequired = "mvp_a_properties_required";
    public const string ModeInvalid = "mode_invalid";
}
