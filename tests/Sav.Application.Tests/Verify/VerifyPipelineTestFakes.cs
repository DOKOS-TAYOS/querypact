using Sav.Application.Abstractions;
using Sav.Domain.Analysis;
using Sav.Domain.Contracts;
using Sav.Domain.Decisions;
using Sav.Domain.Plans;
using Sav.Domain.Policies;
using Sav.Domain.Properties;
using Sav.Domain.Targets;

namespace Sav.Application.Tests.Verify;

internal sealed class PipelineRecordingRedactor : IRedactor
{
    public int RedactObjectCalls { get; private set; }

    public string RedactText(string value, DisclosureProfile profile) => value;

    public T RedactObject<T>(T value, DisclosureProfile profile)
    {
        RedactObjectCalls++;
        return value;
    }
}

internal sealed class RecordingSessionFactory : IReadOnlySessionFactory
{
    public int OpenCount { get; private set; }

    public RecordingSession LastSession { get; } = new();

    public Task<IReadOnlySession> OpenReadOnlySessionAsync(
        TargetAlias target,
        CancellationToken cancellationToken)
    {
        OpenCount++;
        return Task.FromResult<IReadOnlySession>(LastSession);
    }
}

internal sealed class RecordingSession : IReadOnlySession
{
    public int DisposeCount { get; private set; }

    public Task ExecuteAsync(string sql, CancellationToken cancellationToken) => Task.CompletedTask;

    public Task<IReadOnlyList<OracleScalarRow>> ExecuteReaderAsync(
        string sql,
        IReadOnlyList<OracleScalarColumn> allowedColumns,
        CancellationToken cancellationToken) =>
        Task.FromResult<IReadOnlyList<OracleScalarRow>>([]);

    public ValueTask DisposeAsync()
    {
        DisposeCount++;
        return ValueTask.CompletedTask;
    }
}

internal sealed class RecordingCatalog : ICatalogResolver
{
    public int EnrichCount { get; private set; }

    public IReadOnlySession? ReceivedSession { get; private set; }

    public Task<SqlAnalysis> EnrichAsync(
        SqlAnalysis analysis,
        TargetAlias target,
        IReadOnlySession session,
        CancellationToken cancellationToken)
    {
        EnrichCount++;
        ReceivedSession = session;
        // Clear unresolved so second policy can Allow when policy denies unresolved.
        SqlIr ir = analysis.Ir;
        SqlIr cleared = new(
            ir.Dialect,
            ir.StatementTypes,
            ir.TablesRead,
            ir.TablesWritten,
            ir.ColumnsRead,
            ir.ColumnsWritten,
            ir.Functions,
            ir.HasMultipleStatements,
            ir.HasDynamicSql,
            unresolvedObjects: [],
            ir.RiskCodes,
            ir.NormalizedSql,
            ir.Fingerprint);
        return Task.FromResult(new SqlAnalysis(cleared, analysis.IsParsable));
    }
}

internal sealed class RecordingPlanProvider : IPlanProvider
{
    private readonly PlanGateOutcome _outcome;

    public RecordingPlanProvider(PlanGateOutcome outcome = PlanGateOutcome.Allow)
    {
        _outcome = outcome;
    }

    public int CallCount { get; private set; }

    public PolicyDecision? LastDecision { get; private set; }

    public IReadOnlySession? LastSession { get; private set; }

    public Task<PlanGateResult> GetEstimatedPlanAsync(
        TargetAlias target,
        string sql,
        PolicyDecision decision,
        Policy policy,
        IReadOnlySession? session,
        CancellationToken cancellationToken)
    {
        CallCount++;
        LastDecision = decision;
        LastSession = session;
        PlanSummary? summary = _outcome == PlanGateOutcome.Allow
            ? new PlanSummary("low", ["Seq Scan"], [])
            : null;
        return Task.FromResult(new PlanGateResult(_outcome, [_outcome.ToString().ToLowerInvariant()], summary));
    }
}

internal sealed class RecordingOracle : IPropertyOracle
{
    private readonly Func<PropertyEvaluationRequest, IReadOnlyList<PropertyResult>> _factory;

    public RecordingOracle(Func<PropertyEvaluationRequest, IReadOnlyList<PropertyResult>>? factory = null)
    {
        _factory = factory ?? (static _ =>
        [
            new PropertyResult("query_succeeds", PropertyStatus.Pass, null),
            new PropertyResult("empty_result", PropertyStatus.Pass, null),
        ]);
    }

    public int CallCount { get; private set; }

    public PropertyEvaluationRequest? LastRequest { get; private set; }

    public Task<IReadOnlyList<PropertyResult>> EvaluateAsync(
        PropertyEvaluationRequest request,
        CancellationToken cancellationToken)
    {
        CallCount++;
        LastRequest = request;
        return Task.FromResult(_factory(request));
    }
}

internal sealed class RecordingGuard : ISchemaFingerprintGuard
{
    public int CaptureCount { get; private set; }

    public int EnsureCount { get; private set; }

    public int FactoryOpenAttempts { get; private set; }

    public List<string> InvocationOrder { get; } = [];

    public List<IReadOnlySession> SessionsSeen { get; } = [];

    public Task<TargetSchemaFingerprint> CaptureBaselineAsync(
        IReadOnlySession session,
        TargetAlias target,
        SqlAnalysis analysis,
        CancellationToken cancellationToken)
    {
        CaptureCount++;
        InvocationOrder.Add("S1_CaptureBaseline");
        SessionsSeen.Add(session);
        return Task.FromResult(new TargetSchemaFingerprint("baseline"));
    }

    public Task EnsureUnchangedAsync(
        IReadOnlySession session,
        TargetAlias target,
        SqlAnalysis analysis,
        TargetSchemaFingerprint baseline,
        DateTimeOffset pipelineStartedUtc,
        CancellationToken cancellationToken)
    {
        EnsureCount++;
        string step = EnsureCount == 1 ? "S2_EnsureUnchanged" : "S3_EnsureUnchanged";
        InvocationOrder.Add(step);
        SessionsSeen.Add(session);
        return Task.CompletedTask;
    }

    public void NoteFactoryOpenAttempt() => FactoryOpenAttempts++;
}

internal sealed class RecordingAliasResolver : ITargetAliasResolver
{
    public int ResolveCount { get; private set; }

    public string? LastAlias { get; private set; }

    public TargetAlias Resolve(string aliasName)
    {
        ResolveCount++;
        LastAlias = aliasName;
        return new TargetAlias(aliasName, "alias-fp");
    }
}

internal sealed class ConfigurableContractLoader : IContractLoader
{
    private readonly Contract _contract;

    public ConfigurableContractLoader(Contract contract)
    {
        _contract = contract;
    }

    public Task<Contract> LoadAsync(string path, CancellationToken cancellationToken) =>
        Task.FromResult(_contract);
}

internal sealed class ScriptedPolicyEngine : IPolicyEngine
{
    private readonly Queue<PolicyDecision> _decisions;

    public ScriptedPolicyEngine(params PolicyDecision[] decisions)
    {
        _decisions = new Queue<PolicyDecision>(decisions);
    }

    public int EvaluateCount { get; private set; }

    public Task<PolicyDecision> EvaluateAsync(
        SqlAnalysis analysis,
        Policy policy,
        CancellationToken cancellationToken)
    {
        EvaluateCount++;
        if (_decisions.Count == 0)
        {
            return Task.FromResult(new PolicyDecision(PolicyOutcome.Allow, [], []));
        }

        return Task.FromResult(_decisions.Dequeue());
    }
}

internal sealed class FixedAliasResolver : ITargetAliasResolver
{
    public TargetAlias Resolve(string aliasName) =>
        new(aliasName, "alias-fp");
}

internal sealed class FixedPathResolver : IConfigPathResolver
{
    public string ResolveUnderConfigRoot(string relativeOrConfiguredPath) =>
        Path.Combine("C:", "config", relativeOrConfiguredPath.Replace('/', Path.DirectorySeparatorChar));
}

internal sealed class FixedPolicyLoader : IPolicyLoader
{
    public Task<Policy> LoadAsync(string path, CancellationToken cancellationToken) =>
        Task.FromResult(new Policy(
            "p",
            "1",
            ["Select"],
            [],
            [],
            [],
            denyUnresolvedObjects: false,
            denyMultipleStatements: true,
            denyUpdateDeleteWithoutPredicate: true,
            maxCostBucket: "high",
            forbiddenPlanNodes: [],
            disclosure: DisclosureProfileMerge.StrictDefaults()));
}

internal sealed class CountingPolicyLoader(IPolicyLoader inner) : IPolicyLoader
{
    private readonly IPolicyLoader _inner = inner ?? throw new ArgumentNullException(nameof(inner));

    public int LoadCount { get; private set; }

    public async Task<Policy> LoadAsync(string path, CancellationToken cancellationToken)
    {
        LoadCount++;
        return await _inner.LoadAsync(path, cancellationToken).ConfigureAwait(false);
    }

    public void Reset() => LoadCount = 0;
}

internal sealed class FixedContractLoader : IContractLoader
{
    public Task<Contract> LoadAsync(string path, CancellationToken cancellationToken) =>
        Task.FromResult(new Contract(
            "c",
            "1",
            [new QuerySucceedsSpec(), new EmptyResultSpec()],
            DisclosureProfileMerge.StrictDefaults()));
}

internal sealed class FixedEquivalenceContractLoader : IContractLoader
{
    public Task<Contract> LoadAsync(string path, CancellationToken cancellationToken) =>
        Task.FromResult(new Contract(
            "c",
            "1",
            [new QueryEquivalentSpec()],
            DisclosureProfileMerge.StrictDefaults()));
}

internal sealed class CountingContractLoader(IContractLoader inner) : IContractLoader
{
    private readonly IContractLoader _inner = inner ?? throw new ArgumentNullException(nameof(inner));

    public int LoadCount { get; private set; }

    public async Task<Contract> LoadAsync(string path, CancellationToken cancellationToken)
    {
        LoadCount++;
        return await _inner.LoadAsync(path, cancellationToken).ConfigureAwait(false);
    }

    public void Reset() => LoadCount = 0;
}

internal sealed class FixedParser : ISqlParser
{
    private readonly bool _success;

    public FixedParser(bool success = true)
    {
        _success = success;
    }

    public SqlParseResult Parse(string sql, CancellationToken cancellationToken)
    {
        if (!_success)
        {
            return new SqlParseResult(false, null, "sql_unparsable", "redacted");
        }

        SqlIr ir = new(
            "postgresql",
            ["Select"],
            ["t"],
            [],
            ["id"],
            [],
            [],
            false,
            false,
            [],
            [],
            "SELECT 1",
            "fp");
        return new SqlParseResult(true, ir, null, null);
    }
}
