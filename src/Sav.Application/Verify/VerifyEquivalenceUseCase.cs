using Sav.Application.Abstractions;
using Sav.Application.Analyze;
using Sav.Application.Attestations;
using Sav.Domain.Analysis;
using Sav.Domain.Attestations;
using Sav.Domain.Contracts;
using Sav.Domain.Decisions;
using Sav.Domain.Errors;
using Sav.Domain.Execution;
using Sav.Domain.Plans;
using Sav.Domain.Policies;
using Sav.Domain.Properties;
using Sav.Domain.Targets;

namespace Sav.Application.Verify;

/// <summary>
/// verify_equivalence: load policy/contract, authorize both SQL texts, one RO session,
/// catalog-enrich both sides, fingerprint the united schema, then run <see cref="QueryEquivalentSpec"/>
/// on the real alias. Plan Deny/Review skips the oracle. Redact + HMAC via <see cref="AttestationFactory"/>.
/// Failures still yield PASS|FAIL|REVIEW|DENY with typed codes (no raw exception leak, no row payloads).
/// </summary>
public sealed class VerifyEquivalenceUseCase : IVerifyEquivalenceUseCase
{
    public const string DefaultSavVersion = AttestationVersionDefaults.DefaultSavVersion;
    public const string AttestationSchemaVersion = AttestationVersionDefaults.AttestationSchemaVersion;
    private const string PropertyName = "query_equivalent";

    private readonly ISqlParser _parser;
    private readonly IPolicyEngine _policyEngine;
    private readonly IPolicyLoader _policyLoader;
    private readonly IContractLoader _contractLoader;
    private readonly IConfigPathResolver _paths;
    private readonly ITargetAliasResolver _aliases;
    private readonly IReadOnlySessionFactory _sessions;
    private readonly ICatalogResolver _catalog;
    private readonly IPlanProvider _plan;
    private readonly IPropertyOracle _oracle;
    private readonly ISchemaFingerprintGuard _guard;
    private readonly AttestationFactory _attestationFactory;
    private readonly IAttestationStore _store;
    private readonly IRedactor _redactor;
    private readonly byte[] _hmacKey;
    private readonly string _savVersion;

    public VerifyEquivalenceUseCase(
        ISqlParser parser,
        IPolicyEngine policyEngine,
        IPolicyLoader policyLoader,
        IContractLoader contractLoader,
        IConfigPathResolver paths,
        ITargetAliasResolver aliases,
        IReadOnlySessionFactory sessions,
        ICatalogResolver catalog,
        IPlanProvider plan,
        IPropertyOracle oracle,
        ISchemaFingerprintGuard guard,
        AttestationFactory attestationFactory,
        IAttestationStore store,
        IRedactor redactor,
        byte[] hmacKey,
        string? savVersion = null)
    {
        _parser = parser ?? throw new ArgumentNullException(nameof(parser));
        _policyEngine = policyEngine ?? throw new ArgumentNullException(nameof(policyEngine));
        _policyLoader = policyLoader ?? throw new ArgumentNullException(nameof(policyLoader));
        _contractLoader = contractLoader ?? throw new ArgumentNullException(nameof(contractLoader));
        _paths = paths ?? throw new ArgumentNullException(nameof(paths));
        _aliases = aliases ?? throw new ArgumentNullException(nameof(aliases));
        _sessions = sessions ?? throw new ArgumentNullException(nameof(sessions));
        _catalog = catalog ?? throw new ArgumentNullException(nameof(catalog));
        _plan = plan ?? throw new ArgumentNullException(nameof(plan));
        _oracle = oracle ?? throw new ArgumentNullException(nameof(oracle));
        _guard = guard ?? throw new ArgumentNullException(nameof(guard));
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

    private static void ValidateContract(Contract contract)
    {
        if (contract.RequiredProperties.Count != 1 ||
            contract.RequiredProperties[0] is not QueryEquivalentSpec)
        {
            throw new SavException(
                SavErrorCode.ContractInvalid,
                "contract_invalid: verify_equivalence requires exactly one query_equivalent property.");
        }
    }

    public async Task<VerifyEquivalenceResponse> ExecuteAsync(
        VerifyEquivalenceRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentException.ThrowIfNullOrWhiteSpace(request.LeftSql);
        ArgumentException.ThrowIfNullOrWhiteSpace(request.RightSql);
        cancellationToken.ThrowIfCancellationRequested();

        DateTimeOffset pipelineStartedUtc = DateTimeOffset.UtcNow;
        DisclosureProfile disclosure = DisclosureProfileMerge.StrictDefaults();
        string sqlHash = ComputePairHash(request.LeftSql, request.RightSql);
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
            ValidateContract(contract);
            disclosure = DisclosureProfileMerge.Intersect(policy.Disclosure, contract.Disclosure);

            policyHash = AttestationMacMaterial.ComputePolicyHash(policy);
            contractHash = AttestationMacMaterial.ComputeContractHash(contract);

            SqlAnalysis leftAnalysis = ToAnalysis(_parser.Parse(request.LeftSql, cancellationToken));
            SqlAnalysis rightAnalysis = ToAnalysis(_parser.Parse(request.RightSql, cancellationToken));

            if (!leftAnalysis.IsParsable || !rightAnalysis.IsParsable)
            {
                return await PersistAsync(
                        AttestationDecision.Deny,
                        SqlIrToStructuralMapper.ToAttestationAnalysis(leftAnalysis),
                        properties: [],
                        sqlHash,
                        contractHash,
                        policyHash,
                        targetFingerprint,
                        disclosure,
                        cancellationToken)
                    .ConfigureAwait(false);
            }

            PolicyDecision leftFirst = await _policyEngine
                .EvaluateAsync(PreCatalogPolicyAnalysis.Create(leftAnalysis), policy, cancellationToken)
                .ConfigureAwait(false);
            PolicyDecision rightFirst = await _policyEngine
                .EvaluateAsync(PreCatalogPolicyAnalysis.Create(rightAnalysis), policy, cancellationToken)
                .ConfigureAwait(false);

            if (IsDenyOrReview(leftFirst) || IsDenyOrReview(rightFirst))
            {
                return await PersistAsync(
                        MapDecision(leftFirst, rightFirst),
                        SqlIrToStructuralMapper.ToAttestationAnalysis(leftAnalysis),
                        properties: [],
                        sqlHash,
                        contractHash,
                        policyHash,
                        targetFingerprint,
                        disclosure,
                        cancellationToken)
                    .ConfigureAwait(false);
            }

            IReadOnlySession? session = null;
            try
            {
                session = await _sessions.OpenReadOnlySessionAsync(target, cancellationToken)
                    .ConfigureAwait(false);

                SqlAnalysis enrichedLeft;
                SqlAnalysis enrichedRight;
                if (_catalog is ICatalogPairResolver pairCatalog)
                {
                    (enrichedLeft, enrichedRight) = await pairCatalog
                        .EnrichPairAsync(leftAnalysis, rightAnalysis, target, session, cancellationToken)
                        .ConfigureAwait(false);
                }
                else
                {
                    enrichedLeft = await _catalog
                        .EnrichAsync(leftAnalysis, target, session, cancellationToken)
                        .ConfigureAwait(false);
                    enrichedRight = await _catalog
                        .EnrichAsync(rightAnalysis, target, session, cancellationToken)
                        .ConfigureAwait(false);
                }

                PolicyDecision leftSecond = await _policyEngine
                    .EvaluateAsync(enrichedLeft, policy, cancellationToken)
                    .ConfigureAwait(false);
                PolicyDecision rightSecond = await _policyEngine
                    .EvaluateAsync(enrichedRight, policy, cancellationToken)
                    .ConfigureAwait(false);

                if (IsDenyOrReview(leftSecond) || IsDenyOrReview(rightSecond))
                {
                    return await PersistAsync(
                            MapDecision(leftSecond, rightSecond),
                            SqlIrToStructuralMapper.ToAttestationAnalysis(enrichedLeft),
                            properties: [],
                            sqlHash,
                            contractHash,
                            policyHash,
                            targetFingerprint,
                            disclosure,
                            cancellationToken)
                        .ConfigureAwait(false);
                }

                SqlAnalysis fingerprintAnalysis = UnionRelationsForFingerprint(enrichedLeft, enrichedRight);
                TargetSchemaFingerprint baseline = await _guard
                    .CaptureBaselineAsync(session, target, fingerprintAnalysis, cancellationToken)
                    .ConfigureAwait(false);
                await _guard
                    .EnsureUnchangedAsync(
                        session,
                        target,
                        fingerprintAnalysis,
                        baseline,
                        pipelineStartedUtc,
                        cancellationToken)
                    .ConfigureAwait(false);

                PlanGateResult leftPlan = await _plan
                    .GetEstimatedPlanAsync(
                        target,
                        request.LeftSql,
                        leftSecond,
                        policy,
                        session,
                        cancellationToken)
                    .ConfigureAwait(false);
                if (leftPlan.Outcome is PlanGateOutcome.Deny or PlanGateOutcome.Review)
                {
                    AttestationDecision mapped = leftPlan.Outcome == PlanGateOutcome.Review
                        ? AttestationDecision.Review
                        : AttestationDecision.Deny;
                    return await PersistAsync(
                            mapped,
                            SqlIrToStructuralMapper.ToAttestationAnalysis(enrichedLeft),
                            properties: [],
                            sqlHash,
                            contractHash,
                            policyHash,
                            targetFingerprint,
                            disclosure,
                            cancellationToken)
                        .ConfigureAwait(false);
                }

                PlanGateResult rightPlan = await _plan
                    .GetEstimatedPlanAsync(
                        target,
                        request.RightSql,
                        rightSecond,
                        policy,
                        session,
                        cancellationToken)
                    .ConfigureAwait(false);
                if (rightPlan.Outcome is PlanGateOutcome.Deny or PlanGateOutcome.Review)
                {
                    AttestationDecision mapped = rightPlan.Outcome == PlanGateOutcome.Review
                        ? AttestationDecision.Review
                        : AttestationDecision.Deny;
                    return await PersistAsync(
                            mapped,
                            SqlIrToStructuralMapper.ToAttestationAnalysis(enrichedLeft),
                            properties: [],
                            sqlHash,
                            contractHash,
                            policyHash,
                            targetFingerprint,
                            disclosure,
                            cancellationToken)
                        .ConfigureAwait(false);
                }

                await _guard
                    .EnsureUnchangedAsync(
                        session,
                        target,
                        fingerprintAnalysis,
                        baseline,
                        pipelineStartedUtc,
                        cancellationToken)
                    .ConfigureAwait(false);

                IReadOnlyList<PropertyResult> properties = await _oracle
                    .EvaluateAsync(
                        new PropertyEvaluationRequest(
                            ExecutionEnvironment.RealReadOnlyAlias,
                            enrichedLeft.Ir,
                            [new QueryEquivalentSpec()],
                            agentSql: null,
                            leftSql: request.LeftSql,
                            rightSql: request.RightSql,
                            target,
                            session,
                            schemaBefore: null,
                            schemaAfter: null,
                            disclosure,
                            allowedFunctions: policy.AllowedFunctions,
                            rightIr: enrichedRight.Ir),
                        cancellationToken)
                    .ConfigureAwait(false);

                AttestationDecision decision = AttestationDecisionMapper.Map(
                    isParsable: true,
                    policyOutcome: PolicyOutcome.Allow,
                    planGateOutcome: PlanGateOutcome.Allow,
                    requiredPropertyStatuses: properties.Select(static p => p.Status).ToArray());

                return await PersistAsync(
                        decision,
                        SqlIrToStructuralMapper.ToAttestationAnalysis(enrichedLeft),
                        properties,
                        sqlHash,
                        contractHash,
                        policyHash,
                        targetFingerprint,
                        disclosure,
                        cancellationToken)
                    .ConfigureAwait(false);
            }
            finally
            {
                if (session is not null)
                {
                    await session.DisposeAsync().ConfigureAwait(false);
                }
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (SavException ex) when (ex.Code == SavErrorCode.SchemaChanged)
        {
            AttestationAnalysis analysis = VerificationAttestationHelpers.WithSchemaChangedRisk(
                BuildAnalysis(request.LeftSql, cancellationToken));
            return await PersistAsync(
                    AttestationDecision.Review,
                    analysis,
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
                    BuildAnalysis(request.LeftSql, cancellationToken),
                    properties:
                    [
                        new PropertyResult(PropertyName, status, code),
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
                    BuildAnalysis(request.LeftSql, cancellationToken),
                    properties:
                    [
                        new PropertyResult(PropertyName, PropertyStatus.Error, SavErrorCode.QueryFailed),
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

    /// <summary>
    /// Fingerprint material must cover relations from both sides of the equivalence pair
    /// so right-only schema drift is visible to <see cref="ISchemaFingerprintGuard"/>.
    /// </summary>
    private static SqlAnalysis UnionRelationsForFingerprint(SqlAnalysis left, SqlAnalysis right)
    {
        SqlIr l = left.Ir;
        SqlIr r = right.Ir;
        string[] tablesRead = UnionNames(l.TablesRead, r.TablesRead);
        string[] tablesWritten = UnionNames(l.TablesWritten, r.TablesWritten);
        SqlIr united = new(
            dialect: l.Dialect,
            statementTypes: l.StatementTypes,
            tablesRead: tablesRead,
            tablesWritten: tablesWritten,
            columnsRead: l.ColumnsRead,
            columnsWritten: l.ColumnsWritten,
            functions: l.Functions,
            hasMultipleStatements: l.HasMultipleStatements,
            hasDynamicSql: l.HasDynamicSql,
            unresolvedObjects: l.UnresolvedObjects,
            riskCodes: l.RiskCodes,
            normalizedSql: l.NormalizedSql,
            fingerprint: l.Fingerprint,
            operators: l.Operators,
            functionReferences: l.FunctionReferences,
            typeReferences: UnionNames(l.TypeReferences, r.TypeReferences));
        return new SqlAnalysis(united, left.IsParsable && right.IsParsable);
    }

    private static string[] UnionNames(IReadOnlyList<string> left, IReadOnlyList<string> right) =>
        left.Concat(right)
            .Distinct(StringComparer.Ordinal)
            .OrderBy(static n => n, StringComparer.Ordinal)
            .ToArray();

    private static bool IsDenyOrReview(PolicyDecision decision) =>
        decision.Outcome is PolicyOutcome.Deny or PolicyOutcome.Review;

    private static AttestationDecision MapDecision(PolicyDecision left, PolicyDecision right) =>
        left.Outcome == PolicyOutcome.Deny || right.Outcome == PolicyOutcome.Deny
            ? AttestationDecision.Deny
            : AttestationDecision.Review;

    private AttestationAnalysis BuildAnalysis(string sql, CancellationToken cancellationToken) =>
        SqlIrToStructuralMapper.ToAttestationAnalysis(ToAnalysis(_parser.Parse(sql, cancellationToken)));

    private static SqlAnalysis ToAnalysis(SqlParseResult parse) =>
        parse.Success && parse.Ir is not null
            ? new SqlAnalysis(parse.Ir, IsParsable: true)
            : new SqlAnalysis(SqlIrFactory.CreateUnparsable(), IsParsable: false);

    private static string ComputePairHash(string leftSql, string rightSql) =>
        AttestationMacMaterial.ComputeSqlHash((leftSql ?? string.Empty) + "\u0000" + (rightSql ?? string.Empty));

    private async Task<VerifyEquivalenceResponse> PersistAsync(
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

        VerifyEquivalenceResponse response = new(savedId, attestation);
        return _redactor.RedactObject(response, disclosure);
    }

}
