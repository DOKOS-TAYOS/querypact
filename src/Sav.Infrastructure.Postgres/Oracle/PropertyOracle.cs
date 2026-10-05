using Sav.Application.Abstractions;
using Sav.Domain.Analysis;
using Sav.Domain.Contracts;
using Sav.Domain.Decisions;
using Sav.Domain.Errors;
using Sav.Domain.Execution;
using Sav.Domain.Properties;
using Sav.Infrastructure.Postgres.Oracle.Properties;
using Sav.Infrastructure.Postgres.Targets;

namespace Sav.Infrastructure.Postgres.Oracle;

/// <summary>
/// Closed property oracle dispatcher. MVP-A + MVP-B closed property set.
/// </summary>
public sealed class PropertyOracle : IPropertyOracle
{
    private readonly IRedactor _redactor;
    private readonly IReadOnlyList<string> _defaultAllowedFunctions;
    private readonly EphemeralSessionFactory? _ephemeralSessionFactory;
    private readonly string? _ephemeralConnectionString;

    public PropertyOracle(
        IRedactor redactor,
        IReadOnlyList<string>? allowedFunctions = null,
        EphemeralSessionFactory? ephemeralSessionFactory = null,
        string? ephemeralConnectionString = null)
    {
        ArgumentNullException.ThrowIfNull(redactor);
        _redactor = redactor;
        _defaultAllowedFunctions = allowedFunctions?.ToArray() ?? [];
        _ephemeralSessionFactory = ephemeralSessionFactory;
        _ephemeralConnectionString = ephemeralConnectionString;
    }

    public async Task<IReadOnlyList<PropertyResult>> EvaluateAsync(
        PropertyEvaluationRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();

        if (CanBatch(request))
        {
            IOracleBatchReadSession batchSession = (IOracleBatchReadSession)request.Session!;
            List<OracleBatchReadCommand> commands;
            try
            {
                commands = BuildBatchCommands(request);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch
            {
                return await EvaluateSequentiallyAsync(request, cancellationToken).ConfigureAwait(false);
            }

            try
            {
                IReadOnlyList<IReadOnlyList<OracleScalarRow>> rows = await batchSession
                    .ExecuteBatchAsync(commands, cancellationToken)
                    .ConfigureAwait(false);
                if (rows.Count != request.Specs.Count)
                {
                    throw new InvalidOperationException("Oracle batch returned an unexpected result count.");
                }

                List<PropertyResult> batchResults = new(request.Specs.Count);
                for (int i = 0; i < request.Specs.Count; i++)
                {
                    batchResults.Add(MapWrappedReadRows(request.Specs[i], rows[i]));
                }

                return batchResults;
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch
            {
                return await EvaluateSequentiallyAsync(request, cancellationToken).ConfigureAwait(false);
            }
        }

        return await EvaluateSequentiallyAsync(request, cancellationToken).ConfigureAwait(false);
    }

    private async Task<IReadOnlyList<PropertyResult>> EvaluateSequentiallyAsync(
        PropertyEvaluationRequest request,
        CancellationToken cancellationToken)
    {
        List<PropertyResult> results = new(request.Specs.Count);
        foreach (PropertySpec spec in request.Specs)
        {
            results.Add(await EvaluateOneAsync(request, spec, cancellationToken).ConfigureAwait(false));
        }

        return results;
    }

    private static bool CanBatch(PropertyEvaluationRequest request) =>
        request.Environment == ExecutionEnvironment.RealReadOnlyAlias
        && request.Specs.Count >= 2
        && request.Session is IOracleBatchReadSession
        && request.Ir.Functions.Count == 0
        && request.Specs.All(spec => spec is QuerySucceedsSpec or EmptyResultSpec or UniqueSpec or NonNullSpec);

    private List<OracleBatchReadCommand> BuildBatchCommands(PropertyEvaluationRequest request)
    {
        List<OracleBatchReadCommand> commands = new(request.Specs.Count);
        foreach (PropertySpec spec in request.Specs)
        {
            (OracleSqlTemplateKind kind, string? column, OracleScalarColumn scalar) = spec switch
            {
                QuerySucceedsSpec => (OracleSqlTemplateKind.QuerySucceedsExists, null, OracleSqlTemplate.LongVColumn),
                EmptyResultSpec => (OracleSqlTemplateKind.EmptyResultNotExists, null, OracleSqlTemplate.BoolVColumn),
                UniqueSpec unique => (OracleSqlTemplateKind.UniqueDistinctCount, unique.Column, OracleSqlTemplate.LongVColumn),
                NonNullSpec nonNull => (OracleSqlTemplateKind.NonNullIsNullCount, nonNull.Column, OracleSqlTemplate.LongVColumn),
                _ => throw new InvalidOperationException("Unsupported property in oracle batch."),
            };
            string sql = OracleSqlBoundary.BuildWrappedCommand(
                kind,
                request.Ir,
                request.AgentSql ?? throw new SavException(SavErrorCode.UnsupportedConstruct, "unsupported_construct"),
                AllowedFunctionsFor(request),
                column);
            commands.Add(new OracleBatchReadCommand(sql, [scalar]));
        }

        return commands;
    }

    private IReadOnlyList<string> AllowedFunctionsFor(PropertyEvaluationRequest request) =>
        request.AllowedFunctions ?? _defaultAllowedFunctions;

    private static PropertyResult MapWrappedReadRows(PropertySpec spec, IReadOnlyList<OracleScalarRow> rows) => spec switch
    {
        QuerySucceedsSpec => QuerySucceedsProperty.MapRows(rows),
        EmptyResultSpec => EmptyResultProperty.MapRows(rows),
        UniqueSpec => UniqueProperty.MapRows(rows),
        NonNullSpec => NonNullProperty.MapRows(rows),
        _ => new PropertyResult(spec.Name, PropertyStatus.NotEvaluated, null),
    };

    private async Task<PropertyResult> EvaluateOneAsync(
        PropertyEvaluationRequest request,
        PropertySpec spec,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        return spec switch
        {
            AffectedRowsSpec affected => await EvaluateAffectedRowsAsync(request, affected, cancellationToken)
                .ConfigureAwait(false),
            QueryEquivalentSpec => await EvaluateQueryEquivalentAsync(request, cancellationToken)
                .ConfigureAwait(false),
            SchemaInvariantSpec schema => EvaluateSchemaInvariant(request, schema),
            NoNewOrphansSpec orphans => await EvaluateNoNewOrphansAsync(request, orphans, cancellationToken)
                .ConfigureAwait(false),
            QuerySucceedsSpec or EmptyResultSpec or UniqueSpec or NonNullSpec =>
                await EvaluateWrappedReadAsync(request, spec, cancellationToken).ConfigureAwait(false),
            _ => new PropertyResult(spec.Name, PropertyStatus.NotEvaluated, null),
        };
    }

    private static PropertyResult EvaluateSchemaInvariant(
        PropertyEvaluationRequest request,
        SchemaInvariantSpec spec)
    {
        if (request.Environment == ExecutionEnvironment.RealReadOnlyAlias)
        {
            return Error("schema_invariant", SavErrorCode.PropertyEnvironmentForbidden);
        }

        if (request.Environment != ExecutionEnvironment.EphemeralContainer)
        {
            return Error("schema_invariant", SavErrorCode.PropertyEnvironmentForbidden);
        }

        if (request.SchemaBefore is null || request.SchemaAfter is null)
        {
            return Error("schema_invariant", SavErrorCode.UnsupportedConstruct);
        }

        return SchemaInvariantProperty.Evaluate(request.SchemaBefore, request.SchemaAfter, spec);
    }

    private async Task<PropertyResult> EvaluateNoNewOrphansAsync(
        PropertyEvaluationRequest request,
        NoNewOrphansSpec spec,
        CancellationToken cancellationToken)
    {
        if (request.Environment == ExecutionEnvironment.RealReadOnlyAlias)
        {
            return Error("no_new_orphans", SavErrorCode.PropertyEnvironmentForbidden);
        }

        if (request.Environment != ExecutionEnvironment.EphemeralContainer)
        {
            return Error("no_new_orphans", SavErrorCode.PropertyEnvironmentForbidden);
        }

        if (_ephemeralSessionFactory is null || string.IsNullOrWhiteSpace(_ephemeralConnectionString))
        {
            return Error("no_new_orphans", SavErrorCode.SessionRequired);
        }

        try
        {
            string sql = OracleSqlBoundary.BuildNoNewOrphansCommand(
                spec.ParentTable,
                spec.ParentKey,
                spec.ChildTable,
                spec.ChildKey);

            await using EphemeralSession session = await _ephemeralSessionFactory
                .OpenAsync(_ephemeralConnectionString, cancellationToken)
                .ConfigureAwait(false);

            return await NoNewOrphansProperty
                .EvaluateAsync(session, sql, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (SavException ex)
        {
            return Error("no_new_orphans", MapCode(ex.Code));
        }
        catch (Exception ex)
        {
            OracleSqlBoundary.RedactEgress(
                _redactor,
                request.EffectiveDisclosure,
                ex.Message);
            return Error("no_new_orphans", SavErrorCode.QueryFailed);
        }
    }

    private async Task<PropertyResult> EvaluateAffectedRowsAsync(
        PropertyEvaluationRequest request,
        AffectedRowsSpec spec,
        CancellationToken cancellationToken)
    {
        if (request.Environment == ExecutionEnvironment.RealReadOnlyAlias)
        {
            return Error("affected_rows", SavErrorCode.PropertyEnvironmentForbidden);
        }

        if (request.Environment != ExecutionEnvironment.EphemeralContainer)
        {
            return Error("affected_rows", SavErrorCode.PropertyEnvironmentForbidden);
        }

        if (string.IsNullOrWhiteSpace(request.AgentSql))
        {
            return Error("affected_rows", SavErrorCode.UnsupportedConstruct);
        }

        if (_ephemeralSessionFactory is null || string.IsNullOrWhiteSpace(_ephemeralConnectionString))
        {
            return Error("affected_rows", SavErrorCode.SessionRequired);
        }

        try
        {
            string dml = OracleSqlBoundary.BuildAffectedRowsCommand(request.AgentSql);
            await using EphemeralSession session = await _ephemeralSessionFactory
                .OpenAsync(_ephemeralConnectionString, cancellationToken)
                .ConfigureAwait(false);

            return await AffectedRowsProperty
                .EvaluateAsync(
                    session,
                    dml,
                    spec.MinInclusive,
                    spec.MaxInclusive,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (SavException ex)
        {
            return Error("affected_rows", MapCode(ex.Code));
        }
        catch (Exception ex)
        {
            OracleSqlBoundary.RedactEgress(
                _redactor,
                request.EffectiveDisclosure,
                ex.Message);
            return Error("affected_rows", SavErrorCode.QueryFailed);
        }
    }

    private async Task<PropertyResult> EvaluateQueryEquivalentAsync(
        PropertyEvaluationRequest request,
        CancellationToken cancellationToken)
    {
        SqlIr? rightIr = request.RightIr;
        if (string.IsNullOrWhiteSpace(request.LeftSql)
            || string.IsNullOrWhiteSpace(request.RightSql)
            || rightIr is null)
        {
            return Error("query_equivalent", SavErrorCode.UnsupportedConstruct);
        }

        try
        {
            OracleSqlBoundary.EnsureEquivalentSelectPairSafe(
                request.Ir,
                rightIr,
                request.LeftSql,
                request.RightSql,
                AllowedFunctionsFor(request));

            if (request.Environment == ExecutionEnvironment.RealReadOnlyAlias)
            {
                if (request.Session is null)
                {
                    return Error("query_equivalent", SavErrorCode.SessionRequired);
                }

                IReadOnlySession session = request.Session;
                if (session is IOracleBatchReadSession batchSession)
                {
                    return await QueryEquivalentProperty
                        .EvaluateBatchAsync(
                            batchSession,
                            request.LeftSql!,
                            request.RightSql!,
                            cancellationToken)
                        .ConfigureAwait(false);
                }

                return await QueryEquivalentProperty
                    .EvaluateAsync(
                        (sql, ct) => session.ExecuteReaderAsync(
                            sql,
                            [OracleSqlTemplate.LongVColumn],
                            ct),
                        request.LeftSql,
                        request.RightSql,
                        cancellationToken)
                    .ConfigureAwait(false);
            }

            if (request.Environment != ExecutionEnvironment.EphemeralContainer)
            {
                return Error("query_equivalent", SavErrorCode.PropertyEnvironmentForbidden);
            }

            if (_ephemeralSessionFactory is null || string.IsNullOrWhiteSpace(_ephemeralConnectionString))
            {
                return Error("query_equivalent", SavErrorCode.SessionRequired);
            }

            await using EphemeralSession ephemeral = await _ephemeralSessionFactory
                .OpenAsync(_ephemeralConnectionString, cancellationToken)
                .ConfigureAwait(false);

            return await QueryEquivalentProperty
                .EvaluateAsync(
                    (sql, ct) => ephemeral.ExecuteReaderAsync(
                        sql,
                        [OracleSqlTemplate.LongVColumn],
                        ct),
                    request.LeftSql,
                    request.RightSql,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (SavException ex)
        {
            return Error("query_equivalent", MapCode(ex.Code));
        }
        catch (Exception ex)
        {
            OracleSqlBoundary.RedactEgress(
                _redactor,
                request.EffectiveDisclosure,
                ex.Message);
            return Error("query_equivalent", SavErrorCode.QueryFailed);
        }
    }

    private async Task<PropertyResult> EvaluateWrappedReadAsync(
        PropertyEvaluationRequest request,
        PropertySpec spec,
        CancellationToken cancellationToken)
    {
        if (request.Environment == ExecutionEnvironment.RealReadOnlyAlias && request.Session is null)
        {
            return Error(spec.Name, SavErrorCode.SessionRequired);
        }

        if (string.IsNullOrWhiteSpace(request.AgentSql))
        {
            return Error(spec.Name, SavErrorCode.UnsupportedConstruct);
        }

        try
        {
            (OracleSqlTemplateKind kind, string? column) = spec switch
            {
                QuerySucceedsSpec => (OracleSqlTemplateKind.QuerySucceedsExists, null),
                EmptyResultSpec => (OracleSqlTemplateKind.EmptyResultNotExists, null),
                UniqueSpec u => (OracleSqlTemplateKind.UniqueDistinctCount, u.Column),
                NonNullSpec n => (OracleSqlTemplateKind.NonNullIsNullCount, n.Column),
                _ => throw new InvalidOperationException("Unreachable property spec."),
            };

            string wrapped = OracleSqlBoundary.BuildWrappedCommand(
                kind,
                request.Ir,
                request.AgentSql,
                AllowedFunctionsFor(request),
                column);

            IReadOnlySession session = request.Session
                ?? throw new SavException(SavErrorCode.SessionRequired, "session_required");

            return spec switch
            {
                QuerySucceedsSpec => await QuerySucceedsProperty
                    .EvaluateAsync(session, wrapped, cancellationToken)
                    .ConfigureAwait(false),
                EmptyResultSpec => await EmptyResultProperty
                    .EvaluateAsync(session, wrapped, cancellationToken)
                    .ConfigureAwait(false),
                UniqueSpec => await UniqueProperty
                    .EvaluateAsync(session, wrapped, cancellationToken)
                    .ConfigureAwait(false),
                NonNullSpec => await NonNullProperty
                    .EvaluateAsync(session, wrapped, cancellationToken)
                    .ConfigureAwait(false),
                _ => new PropertyResult(spec.Name, PropertyStatus.NotEvaluated, null),
            };
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (SavException ex)
        {
            return Error(spec.Name, MapCode(ex.Code));
        }
        catch (Exception ex)
        {
            OracleSqlBoundary.RedactEgress(
                _redactor,
                request.EffectiveDisclosure,
                ex.Message);
            return Error(spec.Name, SavErrorCode.QueryFailed);
        }
    }

    private static string MapCode(string code)
    {
        return code switch
        {
            SavErrorCode.UnsafeIdentifier => SavErrorCode.UnsafeIdentifier,
            SavErrorCode.UnsupportedConstruct => SavErrorCode.UnsupportedConstruct,
            SavErrorCode.SessionRequired => SavErrorCode.SessionRequired,
            SavErrorCode.QueryFailed => SavErrorCode.QueryFailed,
            SavErrorCode.EmptyExpectedRows => SavErrorCode.EmptyExpectedRows,
            SavErrorCode.UniqueViolation => SavErrorCode.UniqueViolation,
            SavErrorCode.NullFound => SavErrorCode.NullFound,
            SavErrorCode.PropertyEnvironmentForbidden => SavErrorCode.PropertyEnvironmentForbidden,
            SavErrorCode.NotEquivalent => SavErrorCode.NotEquivalent,
            SavErrorCode.AffectedRowsOutOfRange => SavErrorCode.AffectedRowsOutOfRange,
            SavErrorCode.SchemaInvariantFailed => SavErrorCode.SchemaInvariantFailed,
            SavErrorCode.OrphansFound => SavErrorCode.OrphansFound,
            _ => SavErrorCode.UnsupportedConstruct,
        };
    }

    private static PropertyResult Error(string name, string code)
    {
        return new PropertyResult(name, PropertyStatus.Error, code);
    }
}
