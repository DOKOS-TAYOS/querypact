using Sav.Application.Abstractions;
using Sav.Domain.Analysis;
using Sav.Domain.Contracts;
using Sav.Domain.Decisions;
using Sav.Domain.Policies;

namespace Sav.Application.Analyze;

public sealed class AnalyzeSqlUseCase : IAnalyzeSqlUseCase
{
    private readonly ISqlParser _parser;
    private readonly IPolicyEngine _policyEngine;
    private readonly IPolicyLoader _policyLoader;
    private readonly IContractLoader _contractLoader;
    private readonly IConfigPathResolver _paths;
    private readonly IRedactor _redactor;

    public AnalyzeSqlUseCase(
        ISqlParser parser,
        IPolicyEngine policyEngine,
        IPolicyLoader policyLoader,
        IContractLoader contractLoader,
        IConfigPathResolver paths,
        IRedactor redactor)
    {
        _parser = parser ?? throw new ArgumentNullException(nameof(parser));
        _policyEngine = policyEngine ?? throw new ArgumentNullException(nameof(policyEngine));
        _policyLoader = policyLoader ?? throw new ArgumentNullException(nameof(policyLoader));
        _contractLoader = contractLoader ?? throw new ArgumentNullException(nameof(contractLoader));
        _paths = paths ?? throw new ArgumentNullException(nameof(paths));
        _redactor = redactor ?? throw new ArgumentNullException(nameof(redactor));
    }

    public async Task<AnalyzeSqlResponse> ExecuteAsync(
        AnalyzeSqlRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();

        string policyPath = _paths.ResolveUnderConfigRoot(request.PolicyPath);
        Policy policy = await _policyLoader.LoadAsync(policyPath, cancellationToken).ConfigureAwait(false);

        DisclosureProfile effectiveDisclosure = policy.Disclosure;
        if (!string.IsNullOrWhiteSpace(request.ContractPath))
        {
            string contractPath = _paths.ResolveUnderConfigRoot(request.ContractPath);
            Contract contract = await _contractLoader.LoadAsync(contractPath, cancellationToken)
                .ConfigureAwait(false);
            effectiveDisclosure = DisclosureProfileMerge.Intersect(policy.Disclosure, contract.Disclosure);
        }
        else
        {
            effectiveDisclosure = DisclosureProfileMerge.Intersect(
                policy.Disclosure,
                DisclosureProfileMerge.StrictDefaults());
        }

        cancellationToken.ThrowIfCancellationRequested();
        SqlParseResult parse = _parser.Parse(request.Sql, cancellationToken);

        SqlAnalysis analysis = parse.Success && parse.Ir is not null
            ? new SqlAnalysis(parse.Ir, IsParsable: true)
            : new SqlAnalysis(SqlIrFactory.CreateUnparsable(), IsParsable: false);

        PolicyDecision decision = await _policyEngine
            .EvaluateAsync(analysis, policy, cancellationToken)
            .ConfigureAwait(false);

        IReadOnlyList<string> redactedReasons = decision.Reasons.Count > 0
            ? decision.Reasons
            : parse.Success
                ? []
                : [parse.ErrorCode ?? "sql_unparsable"];

        AnalyzeSqlResponse response = new(
            Decision: decision,
            Analysis: SqlIrToStructuralMapper.ToAttestationAnalysis(analysis),
            RedactedReasons: redactedReasons,
            EffectiveDisclosure: effectiveDisclosure);

        return _redactor.RedactObject(response, effectiveDisclosure);
    }

}
