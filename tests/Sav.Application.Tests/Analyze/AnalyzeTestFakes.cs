using Sav.Application.Abstractions;
using Sav.Domain.Analysis;
using Sav.Domain.Contracts;
using Sav.Domain.Decisions;
using Sav.Domain.Policies;

namespace Sav.Application.Tests.Analyze;

internal sealed class RecordingRedactor : IRedactor
{
    public int RedactObjectCalls { get; private set; }

    public string RedactText(string value, DisclosureProfile profile) => value;

    public T RedactObject<T>(T value, DisclosureProfile profile)
    {
        RedactObjectCalls++;
        return value;
    }
}

internal sealed class FakePathResolver : IConfigPathResolver
{
    public int ResolveCalls { get; private set; }

    public string? LastRelativePath { get; private set; }

    public string LastResolvedPath { get; private set; } = string.Empty;

    public string ResolveUnderConfigRoot(string relativeOrConfiguredPath)
    {
        ResolveCalls++;
        LastRelativePath = relativeOrConfiguredPath;
        LastResolvedPath = Path.Combine(
            "C:",
            "config",
            relativeOrConfiguredPath.Replace('/', Path.DirectorySeparatorChar));
        return LastResolvedPath;
    }
}

internal sealed class FakePolicyLoader : IPolicyLoader
{
    private readonly Policy _policy;

    public FakePolicyLoader(Policy? policy = null)
    {
        _policy = policy ?? new Policy(
            id: "demo",
            version: "1",
            allowedStatementTypes: ["Select"],
            deniedTables: [],
            deniedColumns: [],
            allowedFunctions: [],
            denyUnresolvedObjects: false,
            denyMultipleStatements: true,
            denyUpdateDeleteWithoutPredicate: true,
            maxCostBucket: "high",
            forbiddenPlanNodes: [],
            disclosure: DisclosureProfileMerge.StrictDefaults());
    }

    public int LoadCalls { get; private set; }

    public List<string> LoadedPaths { get; } = [];

    public Task<Policy> LoadAsync(string path, CancellationToken cancellationToken)
    {
        LoadCalls++;
        LoadedPaths.Add(path);
        return Task.FromResult(_policy);
    }
}

internal sealed class FakeContractLoader : IContractLoader
{
    private readonly Contract? _contract;

    public FakeContractLoader(Contract? contract = null)
    {
        _contract = contract;
    }

    public Task<Contract> LoadAsync(string path, CancellationToken cancellationToken)
    {
        if (_contract is null)
        {
            throw new InvalidOperationException("No contract configured for test.");
        }

        return Task.FromResult(_contract);
    }
}

internal sealed class FakeParser : ISqlParser
{
    private readonly bool _success;
    private readonly string _normalizedSql;

    public FakeParser(bool success, string normalizedSql = "SELECT 1")
    {
        _success = success;
        _normalizedSql = normalizedSql;
    }

    public SqlParseResult Parse(string sql, CancellationToken cancellationToken)
    {
        if (!_success)
        {
            return new SqlParseResult(false, null, "sql_unparsable", "redacted_error");
        }

        SqlIr ir = new(
            "postgresql",
            ["Select"],
            ["users"],
            [],
            ["id"],
            [],
            [],
            false,
            false,
            [],
            [],
            _normalizedSql,
            "fp");
        return new SqlParseResult(true, ir, null, null);
    }
}

internal sealed class FakePolicyEngine : IPolicyEngine
{
    private readonly PolicyOutcome _outcome;
    private readonly IReadOnlyList<string> _reasons;

    public FakePolicyEngine(PolicyOutcome outcome, IReadOnlyList<string>? reasons = null)
    {
        _outcome = outcome;
        _reasons = reasons ?? [];
    }

    public Task<PolicyDecision> EvaluateAsync(
        SqlAnalysis analysis,
        Policy policy,
        CancellationToken cancellationToken)
    {
        return Task.FromResult(new PolicyDecision(_outcome, _reasons, _reasons));
    }
}
