using Sav.Application.Abstractions;
using Sav.Application.Analyze;
using Sav.Application.Attestations;
using Sav.Domain.Analysis;
using Sav.Domain.Attestations;
using Sav.Domain.Contracts;
using Sav.Domain.Decisions;
using Sav.Domain.Errors;
using Sav.Domain.Plans;
using Sav.Domain.Policies;
using Sav.Domain.Properties;
using Sav.Domain.Targets;

namespace Sav.Application.Verify;

/// <summary>
/// verify_query: run the pipeline, map to an attestation, redact + HMAC, persist.
/// Schema-changed from the fingerprint guard becomes attestation REVIEW.
/// Other failures still yield PASS|FAIL|REVIEW|DENY with typed codes (no raw exception leak).
/// </summary>
public sealed class VerifyQueryUseCase : IVerifyQueryUseCase
{
    public const string DefaultSavVersion = AttestationVersionDefaults.DefaultSavVersion;
    public const string AttestationSchemaVersion = AttestationVersionDefaults.AttestationSchemaVersion;

    private readonly VerificationPipeline _pipeline;
    private readonly ISqlParser _parser;
    private readonly IPolicyLoader _policyLoader;
    private readonly IContractLoader _contractLoader;
    private readonly IConfigPathResolver _paths;
    private readonly ITargetAliasResolver _aliases;
    private readonly AttestationFactory _attestationFactory;
    private readonly IAttestationStore _store;
    private readonly IRedactor _redactor;
    private readonly byte[] _hmacKey;
    private readonly string _savVersion;

    public VerifyQueryUseCase(
        VerificationPipeline pipeline,
        ISqlParser parser,
        IPolicyLoader policyLoader,
        IContractLoader contractLoader,
        IConfigPathResolver paths,
        ITargetAliasResolver aliases,
        AttestationFactory attestationFactory,
        IAttestationStore store,
        IRedactor redactor,
        byte[] hmacKey,
        string? savVersion = null)
    {
        _pipeline = pipeline ?? throw new ArgumentNullException(nameof(pipeline));
        _parser = parser ?? throw new ArgumentNullException(nameof(parser));
        _policyLoader = policyLoader ?? throw new ArgumentNullException(nameof(policyLoader));
        _contractLoader = contractLoader ?? throw new ArgumentNullException(nameof(contractLoader));
        _paths = paths ?? throw new ArgumentNullException(nameof(paths));
        _aliases = aliases ?? throw new ArgumentNullException(nameof(aliases));
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
    }

    public async Task<VerifyQueryResponse> ExecuteAsync(
        VerifyQueryRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentException.ThrowIfNullOrWhiteSpace(request.Sql);
        cancellationToken.ThrowIfCancellationRequested();

        DateTimeOffset pipelineStartedUtc = DateTimeOffset.UtcNow;
        DisclosureProfile disclosure = DisclosureProfileMerge.StrictDefaults();
        string sqlHash = AttestationMacMaterial.ComputeSqlHash(request.Sql);
        string policyHash = string.Empty;
        string contractHash = string.Empty;
        string targetFingerprint = string.Empty;

        try
        {
            TargetAlias target = _aliases.Resolve(request.TargetAliasName);
            targetFingerprint = target.Fingerprint;
            string policyPath = _paths.ResolveUnderConfigRoot(request.PolicyPath);
            string contractPath = _paths.ResolveUnderConfigRoot(request.ContractPath);

            Policy policy = await _policyLoader.LoadAsync(policyPath, cancellationToken).ConfigureAwait(false);
            Contract contract = await _contractLoader.LoadAsync(contractPath, cancellationToken).ConfigureAwait(false);
            disclosure = DisclosureProfileMerge.Intersect(policy.Disclosure, contract.Disclosure);

            policyHash = AttestationMacMaterial.ComputePolicyHash(policy);
            contractHash = AttestationMacMaterial.ComputeContractHash(contract);
            VerificationPipelineContext context = new(target, policy, contract, disclosure, pipelineStartedUtc);

            VerificationPipelineResult pipelineResult = await _pipeline
                .ExecuteAsync(request, context, cancellationToken)
                .ConfigureAwait(false);

            return await PersistAsync(
                    pipelineResult.Decision,
                    pipelineResult.Analysis,
                    pipelineResult.PlanSummary,
                    pipelineResult.Properties,
                    sqlHash,
                    contractHash,
                    policyHash,
                    target.Fingerprint,
                    pipelineResult.EffectiveDisclosure,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (SavException ex) when (ex.Code == SavErrorCode.SchemaChanged)
        {
            AttestationAnalysis analysis = VerificationAttestationHelpers.WithSchemaChangedRisk(
                BuildAnalysis(request.Sql, cancellationToken));
            return await PersistAsync(
                    AttestationDecision.Review,
                    analysis,
                    planSummary: null,
                    properties:
                    [
                        new PropertyResult(
                            "schema_fingerprint",
                            PropertyStatus.Fail,
                            SavErrorCode.SchemaChanged),
                    ],
                    sqlHash,
                    contractHash,
                    policyHash,
                    targetFingerprint,
                    disclosure,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (SavException ex)
        {
            string code = FixedPropertyDetailCodes.Coerce(ex.Code);
            AttestationDecision decision = VerificationAttestationHelpers.MapSavExceptionDecision(ex.Code);
            PropertyStatus status = decision == AttestationDecision.Fail
                ? PropertyStatus.Fail
                : PropertyStatus.Error;

            return await PersistAsync(
                    decision,
                    BuildAnalysis(request.Sql, cancellationToken),
                    planSummary: null,
                    properties:
                    [
                        new PropertyResult("verify_query", status, code),
                    ],
                    sqlHash,
                    contractHash,
                    policyHash,
                    targetFingerprint,
                    disclosure,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception)
        {
            return await PersistAsync(
                    AttestationDecision.Deny,
                    BuildAnalysis(request.Sql, cancellationToken),
                    planSummary: null,
                    properties:
                    [
                        new PropertyResult(
                            "verify_query",
                            PropertyStatus.Error,
                            SavErrorCode.QueryFailed),
                    ],
                    sqlHash,
                    contractHash,
                    policyHash,
                    targetFingerprint,
                    disclosure,
                    cancellationToken)
                .ConfigureAwait(false);
        }
    }

    private AttestationAnalysis BuildAnalysis(string sql, CancellationToken cancellationToken)
    {
        SqlParseResult parse = _parser.Parse(sql, cancellationToken);
        SqlAnalysis analysis = parse.Success && parse.Ir is not null
            ? new SqlAnalysis(parse.Ir, IsParsable: true)
            : new SqlAnalysis(SqlIrFactory.CreateUnparsable(), IsParsable: false);
        return SqlIrToStructuralMapper.ToAttestationAnalysis(analysis);
    }

    private async Task<VerifyQueryResponse> PersistAsync(
        AttestationDecision decision,
        AttestationAnalysis analysis,
        PlanSummary? planSummary,
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
            PlanSummary: planSummary,
            Properties: properties,
            EffectiveDisclosure: disclosure,
            Timestamp: DateTimeOffset.UtcNow);

        Attestation attestation = _attestationFactory.Create(draft, _hmacKey);
        string savedId = await _store.SaveAsync(attestation, cancellationToken).ConfigureAwait(false);

        VerifyQueryResponse response = new(savedId, attestation);
        return _redactor.RedactObject(response, disclosure);
    }
}
