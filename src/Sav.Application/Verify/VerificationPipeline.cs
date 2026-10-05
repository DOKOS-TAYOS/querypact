using Sav.Application.Abstractions;
using Sav.Application.Analyze;
using Sav.Domain.Analysis;
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
/// Shared verify_query pipeline: policy short-circuits, one session per Allow path,
/// fingerprint → plan → oracle. Real-alias props: query_succeeds, empty_result, unique, non_null.
/// Ephemeral-only props on a real alias return <c>property_environment_forbidden</c>.
/// <c>query_equivalent</c> / unknown → <c>unsupported_construct</c>.
/// </summary>
public sealed class VerificationPipeline
{
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
    private readonly IRedactor _redactor;

    public VerificationPipeline(
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
        IRedactor redactor)
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
        _redactor = redactor ?? throw new ArgumentNullException(nameof(redactor));
    }

    public async Task<VerificationPipelineResult> ExecuteAsync(
        VerifyQueryRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentException.ThrowIfNullOrWhiteSpace(request.Sql);
        cancellationToken.ThrowIfCancellationRequested();

        DateTimeOffset pipelineStartedUtc = DateTimeOffset.UtcNow;
        TargetAlias target = _aliases.Resolve(request.TargetAliasName);
        string policyPath = _paths.ResolveUnderConfigRoot(request.PolicyPath);
        string contractPath = _paths.ResolveUnderConfigRoot(request.ContractPath);

        Policy policy = await _policyLoader.LoadAsync(policyPath, cancellationToken).ConfigureAwait(false);
        Contract contract = await _contractLoader.LoadAsync(contractPath, cancellationToken).ConfigureAwait(false);
        DisclosureProfile disclosure = DisclosureProfileMerge.Intersect(policy.Disclosure, contract.Disclosure);

        VerificationPipelineContext context = new(target, policy, contract, disclosure, pipelineStartedUtc);
        return await ExecuteAsync(request, context, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Runs verification using configuration that was already resolved by the caller.
    /// </summary>
    public async Task<VerificationPipelineResult> ExecuteAsync(
        VerifyQueryRequest request,
        VerificationPipelineContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(context);
        ArgumentException.ThrowIfNullOrWhiteSpace(request.Sql);
        cancellationToken.ThrowIfCancellationRequested();

        TargetAlias target = context.Target;
        Policy policy = context.Policy;
        Contract contract = context.Contract;
        DisclosureProfile disclosure = context.EffectiveDisclosure;

        SqlParseResult parse = _parser.Parse(request.Sql, cancellationToken);
        SqlAnalysis analysis = parse.Success && parse.Ir is not null
            ? new SqlAnalysis(parse.Ir, IsParsable: true)
            : new SqlAnalysis(SqlIrFactory.CreateUnparsable(), IsParsable: false);

        PolicyDecision firstDecision = await _policyEngine
            .EvaluateAsync(PreCatalogPolicyAnalysis.Create(analysis), policy, cancellationToken)
            .ConfigureAwait(false);

        if (!analysis.IsParsable || firstDecision.Outcome is PolicyOutcome.Deny or PolicyOutcome.Review)
        {
            AttestationDecision denyDecision = MapFirstPolicyDecision(analysis.IsParsable, firstDecision.Outcome);
            IReadOnlyList<string> reasons = firstDecision.Reasons.Count > 0
                ? firstDecision.Reasons
                : analysis.IsParsable
                    ? []
                    : [parse.ErrorCode ?? "sql_unparsable"];

            return Redact(new VerificationPipelineResult(
                denyDecision,
                SqlIrToStructuralMapper.ToAttestationAnalysis(analysis),
                PlanSummary: null,
                Properties: [],
                disclosure,
                reasons));
        }

        // Fail closed before RO session / plan when no real-alias-relevant specs remain.
        (IReadOnlyList<PropertySpec> allowedSpecs, IReadOnlyList<PropertyResult> forbiddenResults) =
            SelectVerifyQueryProperties(contract);
        if (allowedSpecs.Count == 0 && forbiddenResults.Count == 0)
        {
            return Redact(new VerificationPipelineResult(
                AttestationDecision.Review,
                SqlIrToStructuralMapper.ToAttestationAnalysis(analysis),
                PlanSummary: null,
                Properties:
                [
                    new PropertyResult(
                        "mvp_a_properties",
                        PropertyStatus.NotEvaluated,
                        SavErrorCode.MvpAPropertiesRequired),
                ],
                disclosure,
                RedactedReasons: [SavErrorCode.MvpAPropertiesRequired]));
        }

        // Ephemeral-only specs on real alias: surface forbidden without session/oracle.
        if (allowedSpecs.Count == 0)
        {
            AttestationDecision forbiddenDecision = AttestationDecisionMapper.Map(
                isParsable: true,
                policyOutcome: PolicyOutcome.Allow,
                planGateOutcome: null,
                requiredPropertyStatuses: forbiddenResults.Select(static p => p.Status).ToArray());

            return Redact(new VerificationPipelineResult(
                forbiddenDecision,
                SqlIrToStructuralMapper.ToAttestationAnalysis(analysis),
                PlanSummary: null,
                Properties: forbiddenResults,
                disclosure,
                RedactedReasons: []));
        }

        IReadOnlySession? session = null;
        try
        {
            session = await _sessions.OpenReadOnlySessionAsync(target, cancellationToken)
                .ConfigureAwait(false);

            SqlAnalysis enriched = await _catalog
                .EnrichAsync(analysis, target, session, cancellationToken)
                .ConfigureAwait(false);

            PolicyDecision secondDecision = await _policyEngine
                .EvaluateAsync(enriched, policy, cancellationToken)
                .ConfigureAwait(false);

            if (secondDecision.Outcome is PolicyOutcome.Deny or PolicyOutcome.Review)
            {
                AttestationDecision mapped = secondDecision.Outcome == PolicyOutcome.Review
                    ? AttestationDecision.Review
                    : AttestationDecision.Deny;

                return Redact(new VerificationPipelineResult(
                    mapped,
                    SqlIrToStructuralMapper.ToAttestationAnalysis(enriched),
                    PlanSummary: null,
                    Properties: [],
                    disclosure,
                    secondDecision.Reasons));
            }

            // Second Allow: plan runs here for Deny/Review short-circuit; oracle waits for Allow.
            TargetSchemaFingerprint baseline = await _guard
                .CaptureBaselineAsync(session, target, enriched, cancellationToken)
                .ConfigureAwait(false);
            await _guard
                .EnsureUnchangedAsync(session, target, enriched, baseline, context.PipelineStartedUtc, cancellationToken)
                .ConfigureAwait(false);

            PlanGateResult planResult = await _plan
                .GetEstimatedPlanAsync(
                    target,
                    request.Sql,
                    secondDecision,
                    policy,
                    session,
                    cancellationToken)
                .ConfigureAwait(false);

            if (planResult.Outcome is PlanGateOutcome.Deny or PlanGateOutcome.Review)
            {
                AttestationDecision mapped = planResult.Outcome == PlanGateOutcome.Review
                    ? AttestationDecision.Review
                    : AttestationDecision.Deny;

                return Redact(new VerificationPipelineResult(
                    mapped,
                    SqlIrToStructuralMapper.ToAttestationAnalysis(enriched),
                    planResult.Summary,
                    Properties: [],
                    disclosure,
                    planResult.Reasons));
            }

            // Plan Allow: S3 then oracle with real-alias-allowed properties; append forbidden results.
            await _guard
                .EnsureUnchangedAsync(session, target, enriched, baseline, context.PipelineStartedUtc, cancellationToken)
                .ConfigureAwait(false);

            IReadOnlyList<PropertyResult> evaluated = await _oracle
                .EvaluateAsync(
                    new PropertyEvaluationRequest(
                        ExecutionEnvironment.RealReadOnlyAlias,
                        enriched.Ir,
                        allowedSpecs,
                        request.Sql,
                        leftSql: null,
                        rightSql: null,
                        target,
                        session,
                        schemaBefore: null,
                        schemaAfter: null,
                        disclosure,
                        allowedFunctions: policy.AllowedFunctions),
                    cancellationToken)
                .ConfigureAwait(false);

            IReadOnlyList<PropertyResult> properties = evaluated
                .Concat(forbiddenResults)
                .ToArray();

            AttestationDecision attestDecision = AttestationDecisionMapper.Map(
                isParsable: true,
                policyOutcome: PolicyOutcome.Allow,
                planGateOutcome: PlanGateOutcome.Allow,
                requiredPropertyStatuses: properties.Select(static p => p.Status).ToArray());

            return Redact(new VerificationPipelineResult(
                attestDecision,
                SqlIrToStructuralMapper.ToAttestationAnalysis(enriched),
                planResult.Summary,
                properties,
                disclosure,
                RedactedReasons: []));
        }
        finally
        {
            if (session is not null)
            {
                await session.DisposeAsync().ConfigureAwait(false);
            }
        }
    }

    /// <summary>
    /// Real-alias allowed: query_succeeds, empty_result, unique, non_null.
    /// Ephemeral-only → <c>property_environment_forbidden</c> (not passed to oracle).
    /// <c>query_equivalent</c> / unknown → <c>unsupported_construct</c>
    /// (<see cref="VerifyEquivalenceUseCase"/> owns equivalence).
    /// </summary>
    private static (IReadOnlyList<PropertySpec> Allowed, IReadOnlyList<PropertyResult> Forbidden)
        SelectVerifyQueryProperties(Contract contract)
    {
        List<PropertySpec> allowed = [];
        List<PropertyResult> forbidden = [];

        foreach (PropertySpec spec in contract.RequiredProperties)
        {
            switch (spec)
            {
                case QuerySucceedsSpec or EmptyResultSpec or UniqueSpec or NonNullSpec:
                    allowed.Add(spec);
                    break;
                case SchemaInvariantSpec or NoNewOrphansSpec or AffectedRowsSpec:
                    forbidden.Add(new PropertyResult(
                        spec.Name,
                        PropertyStatus.Error,
                        SavErrorCode.PropertyEnvironmentForbidden));
                    break;
                case QueryEquivalentSpec:
                    forbidden.Add(new PropertyResult(
                        spec.Name,
                        PropertyStatus.Error,
                        SavErrorCode.UnsupportedConstruct));
                    break;
                default:
                    forbidden.Add(new PropertyResult(
                        spec.Name,
                        PropertyStatus.Error,
                        SavErrorCode.UnsupportedConstruct));
                    break;
            }
        }

        return (allowed, forbidden);
    }

    private VerificationPipelineResult Redact(
        VerificationPipelineResult result) =>
        _redactor.RedactObject(result, result.EffectiveDisclosure);

    private static AttestationDecision MapFirstPolicyDecision(bool isParsable, PolicyOutcome outcome)
    {
        if (!isParsable || outcome == PolicyOutcome.Deny)
        {
            return AttestationDecision.Deny;
        }

        if (outcome == PolicyOutcome.Review)
        {
            return AttestationDecision.Review;
        }

        return AttestationDecision.Deny;
    }

}
