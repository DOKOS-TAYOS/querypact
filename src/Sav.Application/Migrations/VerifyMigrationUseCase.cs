using Sav.Application.Abstractions;
using Sav.Application.Analyze;
using Sav.Application.Attestations;
using Sav.Domain.Analysis;
using Sav.Domain.Attestations;
using Sav.Domain.Contracts;
using Sav.Domain.Decisions;
using Sav.Domain.Errors;
using Sav.Domain.Policies;
using Sav.Domain.Properties;
using Sav.Domain.Serialization;

namespace Sav.Application.Migrations;

/// <summary>
/// verify_migration: resolve paths → parse → policy (deny/unparsable → DENY, zero shadow apply)
/// → ephemeral apply → properties → redact → attest → store.
/// </summary>
public sealed class VerifyMigrationUseCase : IVerifyMigrationUseCase
{
    public const string EphemeralTargetFingerprintSeed = "ephemeral";
    public const string DefaultSavVersion = AttestationVersionDefaults.DefaultSavVersion;
    public const string AttestationSchemaVersion = AttestationVersionDefaults.AttestationSchemaVersion;

    private readonly ISqlParser _parser;
    private readonly IPolicyEngine _policyEngine;
    private readonly IPolicyLoader _policyLoader;
    private readonly IContractLoader _contractLoader;
    private readonly IConfigPathResolver _paths;
    private readonly IShadowMigrationRunner _shadow;
    private readonly AttestationFactory _attestationFactory;
    private readonly IAttestationStore _store;
    private readonly IRedactor _redactor;
    private readonly byte[] _hmacKey;
    private readonly string _savVersion;
    private readonly TimeSpan _statementTimeout;

    public VerifyMigrationUseCase(
        ISqlParser parser,
        IPolicyEngine policyEngine,
        IPolicyLoader policyLoader,
        IContractLoader contractLoader,
        IConfigPathResolver paths,
        IShadowMigrationRunner shadow,
        AttestationFactory attestationFactory,
        IAttestationStore store,
        IRedactor redactor,
        byte[] hmacKey,
        string? savVersion = null,
        TimeSpan? statementTimeout = null)
    {
        _parser = parser ?? throw new ArgumentNullException(nameof(parser));
        _policyEngine = policyEngine ?? throw new ArgumentNullException(nameof(policyEngine));
        _policyLoader = policyLoader ?? throw new ArgumentNullException(nameof(policyLoader));
        _contractLoader = contractLoader ?? throw new ArgumentNullException(nameof(contractLoader));
        _paths = paths ?? throw new ArgumentNullException(nameof(paths));
        _shadow = shadow ?? throw new ArgumentNullException(nameof(shadow));
        _attestationFactory = attestationFactory ?? throw new ArgumentNullException(nameof(attestationFactory));
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _redactor = redactor ?? throw new ArgumentNullException(nameof(redactor));
        ArgumentNullException.ThrowIfNull(hmacKey);
        if (hmacKey.Length < 32)
        {
            throw new ArgumentException("HMAC key must be at least 32 bytes.", nameof(hmacKey));
        }

        _hmacKey = hmacKey.ToArray();
        _savVersion = string.IsNullOrWhiteSpace(savVersion) ? DefaultSavVersion : savVersion;
        _statementTimeout = statementTimeout ?? TimeSpan.FromSeconds(5);
    }

    public async Task<VerifyMigrationResponse> ExecuteAsync(
        VerifyMigrationRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();

        DisclosureProfile disclosure = DisclosureProfileMerge.StrictDefaults();
        string sqlHash = AttestationMacMaterial.ComputeSqlHash(string.Empty);
        string policyHash = string.Empty;
        string contractHash = string.Empty;
        string targetFp = CanonicalJson.Sha256Hex(EphemeralTargetFingerprintSeed);

        try
        {
            string migrationSql = await ResolveMigrationSqlAsync(request, cancellationToken).ConfigureAwait(false);

            string policyPath = _paths.ResolveUnderConfigRoot(request.PolicyPath);
            string contractPath = _paths.ResolveUnderConfigRoot(request.ContractPath);
            string baseSchemaPath = _paths.ResolveUnderConfigRoot(request.BaseSchemaPath);

            Policy policy = await _policyLoader.LoadAsync(policyPath, cancellationToken).ConfigureAwait(false);
            Contract contract = await _contractLoader.LoadAsync(contractPath, cancellationToken).ConfigureAwait(false);
            disclosure = DisclosureProfileMerge.Intersect(
                policy.Disclosure,
                contract.Disclosure);

            cancellationToken.ThrowIfCancellationRequested();
            SqlParseResult parse = _parser.Parse(migrationSql, cancellationToken);
            SqlAnalysis analysis = parse.Success && parse.Ir is not null
                ? new SqlAnalysis(parse.Ir, IsParsable: true)
                : new SqlAnalysis(SqlIrFactory.CreateUnparsable(), IsParsable: false);

            PolicyDecision decision = await _policyEngine
                .EvaluateAsync(analysis, policy, cancellationToken)
                .ConfigureAwait(false);

            AttestationAnalysis attestationAnalysis = SqlIrToStructuralMapper.ToAttestationAnalysis(analysis);
            sqlHash = AttestationMacMaterial.ComputeSqlHash(migrationSql);
            policyHash = AttestationMacMaterial.ComputePolicyHash(policy);
            contractHash = AttestationMacMaterial.ComputeContractHash(contract);

            if (!analysis.IsParsable || decision.Outcome is PolicyOutcome.Deny or PolicyOutcome.Review)
            {
                AttestationDecision denyDecision = decision.Outcome == PolicyOutcome.Review
                    ? AttestationDecision.Review
                    : AttestationDecision.Deny;

                return await PersistAsync(
                        denyDecision,
                        attestationAnalysis,
                        properties: [],
                        sqlHash,
                        contractHash,
                        policyHash,
                        targetFp,
                        disclosure,
                        cancellationToken)
                    .ConfigureAwait(false);
            }

            string baseSchemaSql = await File.ReadAllTextAsync(baseSchemaPath, cancellationToken)
                .ConfigureAwait(false);

            ShadowMigrationOutcome outcome = await _shadow
                .RunAsync(
                    new ShadowMigrationCommand(
                        baseSchemaSql,
                        migrationSql,
                        SchemaName: "public",
                        contract.RequiredProperties,
                        _statementTimeout,
                        disclosure),
                    cancellationToken)
                .ConfigureAwait(false);

            AttestationDecision attestDecision;
            IReadOnlyList<PropertyResult> properties;
            if (!outcome.Applied)
            {
                attestDecision = AttestationDecision.Fail;
                properties =
                [
                    new PropertyResult(
                        "shadow_apply",
                        PropertyStatus.Fail,
                        ResolveShadowApplyDetail(outcome.RedactedError)),
                ];
            }
            else
            {
                properties = outcome.PropertyResults;
                attestDecision = AttestationDecisionMapper.Map(
                    isParsable: true,
                    policyOutcome: PolicyOutcome.Allow,
                    planGateOutcome: null,
                    requiredPropertyStatuses: properties.Select(p => p.Status).ToArray());
            }

            return await PersistAsync(
                    attestDecision,
                    attestationAnalysis,
                    properties,
                    sqlHash,
                    contractHash,
                    policyHash,
                    targetFp,
                    disclosure,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (SavException ex)
        {
            string code = FixedPropertyDetailCodes.Coerce(ex.Code);
            return await PersistAsync(
                    AttestationDecision.Deny,
                    SqlIrToStructuralMapper.ToAttestationAnalysis(
                        new SqlAnalysis(SqlIrFactory.CreateUnparsable(), IsParsable: false)),
                    properties:
                    [
                        new PropertyResult("verify_migration", PropertyStatus.Error, code),
                    ],
                    sqlHash,
                    contractHash,
                    policyHash,
                    targetFp,
                    disclosure,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception)
        {
            return await PersistAsync(
                    AttestationDecision.Deny,
                    SqlIrToStructuralMapper.ToAttestationAnalysis(
                        new SqlAnalysis(SqlIrFactory.CreateUnparsable(), IsParsable: false)),
                    properties:
                    [
                        new PropertyResult(
                            "verify_migration",
                            PropertyStatus.Error,
                            SavErrorCode.QueryFailed),
                    ],
                    sqlHash,
                    contractHash,
                    policyHash,
                    targetFp,
                    disclosure,
                    cancellationToken)
                .ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Persists only fixed machine codes on <c>shadow_apply.RedactedDetail</c>
    /// (strict <c>IncludeRowCounts=false</c> binding). Free-text PG messages coerce to
    /// <see cref="SavErrorCode.QueryFailed"/>.
    /// </summary>
    private static string ResolveShadowApplyDetail(string? redactedError) =>
        FixedPropertyDetailCodes.Coerce(
            string.IsNullOrWhiteSpace(redactedError) ? null : redactedError.Trim());

    private async Task<string> ResolveMigrationSqlAsync(
        VerifyMigrationRequest request,
        CancellationToken cancellationToken)
    {
        bool hasSql = !string.IsNullOrWhiteSpace(request.MigrationSql);
        bool hasPath = !string.IsNullOrWhiteSpace(request.MigrationPath);
        if (hasSql == hasPath)
        {
            throw new SavException(
                SavErrorCode.UnsupportedConstruct,
                "unsupported_construct: exactly one of MigrationSql or MigrationPath is required.");
        }

        if (hasSql)
        {
            return request.MigrationSql!.Trim();
        }

        string migrationPath = _paths.ResolveUnderConfigRoot(request.MigrationPath!);
        return await File.ReadAllTextAsync(migrationPath, cancellationToken).ConfigureAwait(false);
    }

    private async Task<VerifyMigrationResponse> PersistAsync(
        AttestationDecision decision,
        AttestationAnalysis analysis,
        IReadOnlyList<PropertyResult> properties,
        string sqlHash,
        string contractHash,
        string policyHash,
        string targetFingerprint,
        DisclosureProfile disclosure,
        CancellationToken cancellationToken)
    {
        string id = Guid.NewGuid().ToString("D");
        AttestationDraft draft = new(
            SchemaVersion: AttestationSchemaVersion,
            Id: id,
            SqlHash: sqlHash,
            ContractHash: contractHash,
            PolicyHash: policyHash,
            SavVersion: _savVersion,
            TargetAliasFingerprint: targetFingerprint,
            Decision: decision,
            Analysis: analysis,
            PlanSummary: null,
            Properties: properties,
            EffectiveDisclosure: disclosure,
            Timestamp: DateTimeOffset.UtcNow);

        Attestation attestation = _attestationFactory.Create(draft, _hmacKey);
        string savedId = await _store.SaveAsync(attestation, cancellationToken).ConfigureAwait(false);

        VerifyMigrationResponse response = new(savedId, attestation);
        return _redactor.RedactObject(response, disclosure);
    }

}
