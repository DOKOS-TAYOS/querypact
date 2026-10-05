using Sav.Domain.Analysis;
using Sav.Domain.Contracts;
using Sav.Domain.Execution;
using Sav.Domain.Policies;
using Sav.Domain.Schema;
using Sav.Domain.Targets;

namespace Sav.Application.Abstractions;

/// <summary>
/// Frozen oracle request DTO. <c>Session</c> non-null iff <see cref="ExecutionEnvironment.RealReadOnlyAlias"/>.
/// </summary>
public sealed record PropertyEvaluationRequest
{
    public PropertyEvaluationRequest(
        ExecutionEnvironment environment,
        SqlIr ir,
        IReadOnlyList<PropertySpec> specs,
        string? agentSql,
        string? leftSql,
        string? rightSql,
        TargetAlias? target,
        IReadOnlySession? session,
        SchemaSnapshot? schemaBefore,
        SchemaSnapshot? schemaAfter,
        DisclosureProfile effectiveDisclosure,
        IReadOnlyList<string>? allowedFunctions = null,
        SqlIr? rightIr = null)
    {
        ArgumentNullException.ThrowIfNull(ir);
        ArgumentNullException.ThrowIfNull(specs);
        ArgumentNullException.ThrowIfNull(effectiveDisclosure);

        Environment = environment;
        Ir = ir;
        Specs = specs.ToArray();
        AgentSql = agentSql;
        LeftSql = leftSql;
        RightSql = rightSql;
        Target = target;
        Session = session;
        SchemaBefore = schemaBefore;
        SchemaAfter = schemaAfter;
        EffectiveDisclosure = effectiveDisclosure;
        AllowedFunctions = allowedFunctions?.ToArray();
        RightIr = rightIr;
    }

    public ExecutionEnvironment Environment { get; }

    public SqlIr Ir { get; }

    public IReadOnlyList<PropertySpec> Specs { get; }

    public string? AgentSql { get; }

    public string? LeftSql { get; }

    public string? RightSql { get; }

    public TargetAlias? Target { get; }

    public IReadOnlySession? Session { get; }

    public SchemaSnapshot? SchemaBefore { get; }

    public SchemaSnapshot? SchemaAfter { get; }

    public DisclosureProfile EffectiveDisclosure { get; }

    public IReadOnlyList<string>? AllowedFunctions { get; }

    public SqlIr? RightIr { get; }
}
