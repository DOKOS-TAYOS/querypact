using System.Globalization;
using System.Text;
using Sav.Application.Abstractions;
using Sav.Domain.Analysis;
using Sav.Domain.Targets;

namespace Sav.Infrastructure.Postgres.Catalog;

/// <summary>
/// Catalog enrichment against pg_catalog via the caller-supplied <see cref="IReadOnlySession"/>.
/// Returns existence metadata only: never table row payloads. Does not own sessions or fingerprints.
/// </summary>
public sealed class PgCatalogResolver : ICatalogPairResolver
{
    private static readonly OracleScalarColumn[] ExistsColumns =
    [
        new("v", OracleScalarKind.BoolV),
    ];

    private static readonly OracleScalarColumn[] RelationColumns =
    [
        new("v", OracleScalarKind.BoolV),
        new("kind", OracleScalarKind.StringV),
    ];

    public async Task<SqlAnalysis> EnrichAsync(
        SqlAnalysis analysis,
        TargetAlias target,
        IReadOnlySession session,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(analysis);
        ArgumentNullException.ThrowIfNull(target);
        ArgumentNullException.ThrowIfNull(session);
        cancellationToken.ThrowIfCancellationRequested();

        (SqlAnalysis functionChecked, bool unsafeFunction) =
            await ApplyFunctionSafetyAsync(analysis, session, cancellationToken).ConfigureAwait(false);
        analysis = functionChecked;
        if (unsafeFunction)
        {
            return analysis;
        }

        (SqlAnalysis operatorChecked, bool unsafeOperator) =
            await ApplyOperatorSafetyAsync(analysis, session, cancellationToken).ConfigureAwait(false);
        analysis = operatorChecked;
        if (unsafeOperator || !analysis.IsParsable)
        {
            return analysis;
        }

        if (!await PgConversionSafety.IsSafeAsync([analysis], session, cancellationToken).ConfigureAwait(false))
        {
            return MarkUnsupportedFunction(analysis);
        }

        if (analysis.Ir.UnresolvedObjects.Count == 0)
        {
            return analysis;
        }

        // Keep the product's common single-object path identical to the original query flow.
        if (analysis.Ir.UnresolvedObjects.Count == 1)
        {
            string name = analysis.Ir.UnresolvedObjects[0];
            (bool exists, string? kind) = await ResolveRelationAsync(session, name, cancellationToken)
                .ConfigureAwait(false);
            IReadOnlyList<string> unresolved = exists ? Array.Empty<string>() : [name];
            return CreateEnrichedAnalysis(analysis, unresolved, IsUnsupportedRelationKind(kind));
        }

        List<string> stillUnresolved = [];
        List<ParsedObjectName> safeObjects = [];
        foreach (string name in analysis.Ir.UnresolvedObjects)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (PgCatalogObjectName.TryParse(name, out string? schema, out string relation))
            {
                safeObjects.Add(new ParsedObjectName(name, schema, relation));
            }
            else
            {
                // Fail closed: unparseable / unsafe identifiers stay unresolved and never enter SQL.
                stillUnresolved.Add(name);
            }
        }

        bool unsupportedRelation = false;
        if (safeObjects.Count == 1)
        {
            ParsedObjectName item = safeObjects[0];
            (bool exists, string? kind) = await ResolveRelationAsync(
                session,
                item.Schema,
                item.Relation,
                cancellationToken).ConfigureAwait(false);
            if (!exists)
            {
                stillUnresolved.Add(item.OriginalName);
            }
            return CreateEnrichedAnalysis(
                analysis,
                stillUnresolved,
                IsUnsupportedRelationKind(kind));
        }
        else if (safeObjects.Count > 1)
        {
            IReadOnlyList<OracleScalarRow> rows = await session
                .ExecuteReaderAsync(
                    BuildBatchExistsSql(safeObjects),
                    RelationColumns,
                    cancellationToken)
                .ConfigureAwait(false);

            // A positional mapping is valid only when every requested object has one result row.
            // Keep all safe objects unresolved if the provider returns an unexpected shape.
            if (rows.Count != safeObjects.Count)
            {
                stillUnresolved.AddRange(safeObjects.Select(item => item.OriginalName));
            }
            else
            {
                for (int index = 0; index < safeObjects.Count; index++)
                {
                    OracleScalarRow row = rows[index];
                    unsupportedRelation |= IsUnsupportedRelationKind(row.StringV);
                    if (row.BoolV != true)
                    {
                        stillUnresolved.Add(safeObjects[index].OriginalName);
                    }
                }
            }
        }

        stillUnresolved.Sort(StringComparer.Ordinal);
        return CreateEnrichedAnalysis(analysis, stillUnresolved, unsupportedRelation);
    }

    public async Task<(SqlAnalysis Left, SqlAnalysis Right)> EnrichPairAsync(
        SqlAnalysis left,
        SqlAnalysis right,
        TargetAlias target,
        IReadOnlySession session,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(left);
        ArgumentNullException.ThrowIfNull(right);
        ArgumentNullException.ThrowIfNull(target);
        ArgumentNullException.ThrowIfNull(session);
        cancellationToken.ThrowIfCancellationRequested();

        (SqlAnalysis functionCheckedLeft, SqlAnalysis functionCheckedRight, bool unsafeFunction) =
            await ApplyFunctionSafetyPairAsync(left, right, session, cancellationToken).ConfigureAwait(false);
        left = functionCheckedLeft;
        right = functionCheckedRight;
        if (unsafeFunction)
        {
            return (left, right);
        }

        (SqlAnalysis checkedLeft, SqlAnalysis checkedRight, bool unsafeOperator) =
            await ApplyOperatorSafetyPairAsync(left, right, session, cancellationToken).ConfigureAwait(false);
        left = checkedLeft;
        right = checkedRight;
        if (unsafeOperator)
        {
            return (left, right);
        }

        if (!await PgConversionSafety.IsSafeAsync([left, right], session, cancellationToken).ConfigureAwait(false))
        {
            return (MarkUnsupportedFunction(left), MarkUnsupportedFunction(right));
        }

        List<ParsedObjectName> uniqueSafeObjects = [];
        HashSet<LookupIdentity> seen = [];
        AddSafeObjects(left, uniqueSafeObjects, seen, cancellationToken);
        AddSafeObjects(right, uniqueSafeObjects, seen, cancellationToken);

        Dictionary<LookupIdentity, (bool Exists, string? Kind)> resolved = [];
        if (uniqueSafeObjects.Count == 1)
        {
            ParsedObjectName item = uniqueSafeObjects[0];
            resolved[item.Identity] = await ResolveRelationAsync(session, item.Schema, item.Relation, cancellationToken)
                .ConfigureAwait(false);
        }
        else if (uniqueSafeObjects.Count > 1)
        {
            IReadOnlyList<OracleScalarRow> rows = await session
                .ExecuteReaderAsync(BuildBatchExistsSql(uniqueSafeObjects), RelationColumns, cancellationToken)
                .ConfigureAwait(false);

            // Positional results are trustworthy only when every requested identity has a boolean row.
            if (rows.Count == uniqueSafeObjects.Count && rows.All(static row => row.BoolV.HasValue))
            {
                for (int index = 0; index < uniqueSafeObjects.Count; index++)
                {
                    resolved[uniqueSafeObjects[index].Identity] = (rows[index].BoolV!.Value, rows[index].StringV);
                }
            }
            else
            {
                foreach (ParsedObjectName item in uniqueSafeObjects)
                {
                    resolved[item.Identity] = (false, null);
                }
            }
        }

        return (Project(left, resolved), Project(right, resolved));
    }

    private static async Task<(SqlAnalysis Analysis, bool Unsafe)> ApplyFunctionSafetyAsync(
        SqlAnalysis analysis,
        IReadOnlySession session,
        CancellationToken cancellationToken)
    {
        if (!analysis.IsParsable)
        {
            return (analysis, false);
        }

        string[] unqualified = GetUnqualifiedFunctions(analysis.Ir.FunctionReferences);
        if (unqualified.Length == 0)
        {
            return (analysis, false);
        }

        bool unsafeFunction = await HasVisibleNonCatalogFunctionAsync(session, unqualified, cancellationToken)
            .ConfigureAwait(false);
        return unsafeFunction
            ? (MarkUnsupportedFunction(analysis), true)
            : (analysis, false);
    }

    private static async Task<(SqlAnalysis Left, SqlAnalysis Right, bool Unsafe)> ApplyFunctionSafetyPairAsync(
        SqlAnalysis left,
        SqlAnalysis right,
        IReadOnlySession session,
        CancellationToken cancellationToken)
    {
        string[] unqualified = left.Ir.FunctionReferences
            .Concat(right.Ir.FunctionReferences)
            .Where(static name => !name.Contains('.'))
            .Where(static name => !string.IsNullOrWhiteSpace(name))
            .Distinct(StringComparer.Ordinal)
            .OrderBy(static name => name, StringComparer.Ordinal)
            .ToArray();

        if (unqualified.Length == 0)
        {
            return (left, right, false);
        }

        bool unsafeFunction = await HasVisibleNonCatalogFunctionAsync(session, unqualified, cancellationToken)
            .ConfigureAwait(false);
        if (!unsafeFunction)
        {
            return (left, right, false);
        }

        return (MarkUnsupportedFunction(left), MarkUnsupportedFunction(right), true);
    }

    private static string[] GetUnqualifiedFunctions(IReadOnlyList<string> functions) =>
        functions
            .Where(static name => !string.IsNullOrWhiteSpace(name))
            .Where(static name => !name.Contains('.'))
            .Distinct(StringComparer.Ordinal)
            .OrderBy(static name => name, StringComparer.Ordinal)
            .ToArray();

    private static async Task<bool> HasVisibleNonCatalogFunctionAsync(
        IReadOnlySession session,
        IReadOnlyList<string> functions,
        CancellationToken cancellationToken)
    {
        if (functions.Count == 0)
        {
            return false;
        }

        IReadOnlyList<OracleScalarRow> rows = await session
            .ExecuteReaderAsync(
                BuildVisibleNonCatalogFunctionSql(functions),
                ExistsColumns,
                cancellationToken)
            .ConfigureAwait(false);
        return rows.Count > 0 && rows[0].BoolV == true;
    }

    internal static string BuildVisibleNonCatalogFunctionSql(IReadOnlyList<string> functions)
    {
        ArgumentNullException.ThrowIfNull(functions);
        if (functions.Count == 0)
        {
            throw new ArgumentException("At least one function name is required.", nameof(functions));
        }

        StringBuilder sql = new();
        sql.AppendLine(
            """
            WITH requested(proname) AS (
              VALUES
            """);
        for (int index = 0; index < functions.Count; index++)
        {
            if (index > 0)
            {
                sql.AppendLine(",");
            }

            sql.Append("    ('");
            sql.Append(PgCatalogObjectName.EscapeLiteral(functions[index]));
            sql.Append("'::pg_catalog.name)");
        }

        sql.AppendLine(
            """
            )
            SELECT EXISTS (
              SELECT 1
              FROM requested r
              JOIN pg_catalog.pg_proc p
                ON p.proname OPERATOR(pg_catalog.=) r.proname
              JOIN pg_catalog.pg_namespace n
                ON n.oid OPERATOR(pg_catalog.=) p.pronamespace
              WHERE NOT (
                n.nspname OPERATOR(pg_catalog.=) 'pg_catalog'::pg_catalog.name
              )
                AND pg_catalog.pg_function_is_visible(p.oid)
                AND pg_catalog.has_function_privilege(p.oid, 'EXECUTE')
            ) AS v
            """);
        return sql.ToString();
    }

    private static SqlAnalysis MarkUnsupportedFunction(SqlAnalysis analysis)
    {
        string[] risks = analysis.Ir.RiskCodes
            .Concat(["unsupported_construct"])
            .Distinct(StringComparer.Ordinal)
            .OrderBy(static code => code, StringComparer.Ordinal)
            .ToArray();
        return new SqlAnalysis(
            CloneIr(analysis.Ir, analysis.Ir.UnresolvedObjects, risks),
            analysis.IsParsable);
    }

    private static async Task<(SqlAnalysis Analysis, bool Unsafe)> ApplyOperatorSafetyAsync(
        SqlAnalysis analysis,
        IReadOnlySession session,
        CancellationToken cancellationToken)
    {
        if (!analysis.IsParsable || analysis.Ir.Operators.Count == 0)
        {
            return (analysis, false);
        }

        if (analysis.Ir.Operators.Any(IsExplicitNonCatalogOperator))
        {
            return (MarkUnsupportedOperator(analysis), true);
        }

        string[] unqualified = GetUnqualifiedOperators(analysis.Ir.Operators);
        if (unqualified.Length == 0)
        {
            return (analysis, false);
        }

        bool unsafeOperator = await HasVisibleNonCatalogOperatorAsync(session, unqualified, cancellationToken)
            .ConfigureAwait(false);
        return unsafeOperator
            ? (MarkUnsupportedOperator(analysis), true)
            : (analysis, false);
    }

    private static async Task<(SqlAnalysis Left, SqlAnalysis Right, bool Unsafe)> ApplyOperatorSafetyPairAsync(
        SqlAnalysis left,
        SqlAnalysis right,
        IReadOnlySession session,
        CancellationToken cancellationToken)
    {
        bool unsafeLeft = left.IsParsable && left.Ir.Operators.Any(IsExplicitNonCatalogOperator);
        bool unsafeRight = right.IsParsable && right.Ir.Operators.Any(IsExplicitNonCatalogOperator);
        if (unsafeLeft || unsafeRight)
        {
            return (
                unsafeLeft ? MarkUnsupportedOperator(left) : left,
                unsafeRight ? MarkUnsupportedOperator(right) : right,
                true);
        }

        string[] unqualified = left.Ir.Operators
            .Concat(right.Ir.Operators)
            .Where(static name => !name.Contains('.'))
            .Where(static name => !string.IsNullOrWhiteSpace(name))
            .Distinct(StringComparer.Ordinal)
            .OrderBy(static name => name, StringComparer.Ordinal)
            .ToArray();

        if (unqualified.Length == 0)
        {
            return (left, right, false);
        }

        bool unsafeOperator = await HasVisibleNonCatalogOperatorAsync(session, unqualified, cancellationToken)
            .ConfigureAwait(false);
        if (!unsafeOperator)
        {
            return (left, right, false);
        }

        // Conservative pair semantics: once an unqualified operator name is ambiguous with a
        // visible non-pg_catalog definition, reject the equivalence pair before either query executes.
        return (MarkUnsupportedOperator(left), MarkUnsupportedOperator(right), true);
    }

    private static bool IsExplicitNonCatalogOperator(string name)
    {
        if (string.IsNullOrWhiteSpace(name) || !name.Contains('.'))
        {
            return false;
        }

        string[] parts = name.Split('.', StringSplitOptions.None);
        return parts.Length != 2 || !string.Equals(parts[0], "pg_catalog", StringComparison.Ordinal);
    }

    private static string[] GetUnqualifiedOperators(IReadOnlyList<string> operators) =>
        operators
            .Where(static name => !string.IsNullOrWhiteSpace(name))
            .Where(static name => !name.Contains('.'))
            .Distinct(StringComparer.Ordinal)
            .OrderBy(static name => name, StringComparer.Ordinal)
            .ToArray();

    private static async Task<bool> HasVisibleNonCatalogOperatorAsync(
        IReadOnlySession session,
        IReadOnlyList<string> operators,
        CancellationToken cancellationToken)
    {
        if (operators.Count == 0)
        {
            return false;
        }

        IReadOnlyList<OracleScalarRow> rows = await session
            .ExecuteReaderAsync(
                BuildVisibleNonCatalogOperatorSql(operators),
                ExistsColumns,
                cancellationToken)
            .ConfigureAwait(false);
        return rows.Count > 0 && rows[0].BoolV == true;
    }

    internal static string BuildVisibleNonCatalogOperatorSql(IReadOnlyList<string> operators)
    {
        ArgumentNullException.ThrowIfNull(operators);
        if (operators.Count == 0)
        {
            throw new ArgumentException("At least one operator name is required.", nameof(operators));
        }

        StringBuilder sql = new();
        sql.AppendLine(
            """
            WITH requested(oprname) AS (
              VALUES
            """);
        for (int index = 0; index < operators.Count; index++)
        {
            if (index > 0)
            {
                sql.AppendLine(",");
            }

            sql.Append("    ('");
            sql.Append(PgCatalogObjectName.EscapeLiteral(operators[index]));
            sql.Append("'::pg_catalog.name)");
        }

        sql.AppendLine(
            """
            )
            SELECT EXISTS (
              SELECT 1
              FROM requested r
              JOIN pg_catalog.pg_operator o
                ON o.oprname OPERATOR(pg_catalog.=) r.oprname
              JOIN pg_catalog.pg_namespace n
                ON n.oid OPERATOR(pg_catalog.=) o.oprnamespace
              WHERE NOT (
                n.nspname OPERATOR(pg_catalog.=) 'pg_catalog'::pg_catalog.name
              )
                AND pg_catalog.pg_operator_is_visible(o.oid)
            ) AS v
            """);
        return sql.ToString();
    }

    private static SqlAnalysis MarkUnsupportedOperator(SqlAnalysis analysis)
    {
        string[] risks = analysis.Ir.RiskCodes
            .Concat(["unsupported_construct"])
            .Distinct(StringComparer.Ordinal)
            .OrderBy(static code => code, StringComparer.Ordinal)
            .ToArray();
        return new SqlAnalysis(
            CloneIr(analysis.Ir, analysis.Ir.UnresolvedObjects, risks),
            analysis.IsParsable);
    }

    private static void AddSafeObjects(
        SqlAnalysis analysis,
        List<ParsedObjectName> safeObjects,
        HashSet<LookupIdentity> seen,
        CancellationToken cancellationToken)
    {
        if (!analysis.IsParsable)
        {
            return;
        }

        foreach (string name in analysis.Ir.UnresolvedObjects)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!PgCatalogObjectName.TryParse(name, out string? schema, out string relation))
            {
                continue;
            }

            ParsedObjectName item = new(name, schema, relation);
            if (seen.Add(item.Identity))
            {
                safeObjects.Add(item);
            }
        }
    }

    private static SqlAnalysis Project(
        SqlAnalysis analysis,
        IReadOnlyDictionary<LookupIdentity, (bool Exists, string? Kind)> resolved)
    {
        if (!analysis.IsParsable || analysis.Ir.UnresolvedObjects.Count == 0)
        {
            return analysis;
        }

        List<string> unresolved = [];
        bool unsupportedRelation = false;
        foreach (string name in analysis.Ir.UnresolvedObjects)
        {
            if (!PgCatalogObjectName.TryParse(name, out string? schema, out string relation) ||
                !resolved.TryGetValue(LookupIdentity.Create(schema, relation), out var resolvedRelation))
            {
                unresolved.Add(name);
                continue;
            }

            unsupportedRelation |= IsUnsupportedRelationKind(resolvedRelation.Kind);
            if (!resolvedRelation.Exists)
            {
                unresolved.Add(name);
            }
        }

        unresolved.Sort(StringComparer.Ordinal);
        return CreateEnrichedAnalysis(analysis, unresolved, unsupportedRelation);
    }

    private static async Task<(bool Exists, string? Kind)> ResolveRelationAsync(
        IReadOnlySession session,
        string objectName,
        CancellationToken cancellationToken)
    {
        if (!PgCatalogObjectName.TryParse(objectName, out string? schema, out string relation))
        {
            // Fail closed: unparseable / unsafe identifiers stay unresolved.
            return (false, null);
        }

        return await ResolveRelationAsync(session, schema, relation, cancellationToken).ConfigureAwait(false);
    }

    private static async Task<(bool Exists, string? Kind)> ResolveRelationAsync(
        IReadOnlySession session,
        string? schema,
        string relation,
        CancellationToken cancellationToken)
    {
        string sql = BuildResolveSql(schema, relation);
        IReadOnlyList<OracleScalarRow> rows = await session
            .ExecuteReaderAsync(sql, RelationColumns, cancellationToken)
            .ConfigureAwait(false);
        return rows.Count > 0 ? (rows[0].BoolV == true, rows[0].StringV) : (false, null);
    }

    private static string BuildBatchExistsSql(IReadOnlyList<ParsedObjectName> objects)
    {
        StringBuilder sql = new();
        sql.AppendLine(
            """
            WITH requested(ordinal, schema_name, relation_name) AS (
              VALUES
            """);

        for (int index = 0; index < objects.Count; index++)
        {
            ParsedObjectName item = objects[index];
            if (index > 0)
            {
                sql.AppendLine(",");
            }

            sql.Append("    (");
            sql.Append(index.ToString(CultureInfo.InvariantCulture));
            sql.Append(", ");
            sql.Append(item.Schema is null
                ? "NULL"
                : $"'{PgCatalogObjectName.EscapeLiteral(item.Schema)}'");
            sql.Append(", '");
            sql.Append(PgCatalogObjectName.EscapeLiteral(item.Relation));
            sql.Append("')");
        }

        sql.AppendLine(
            """
            )
            SELECT EXISTS (
              SELECT 1
              FROM pg_catalog.pg_class c
              JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
              WHERE c.relkind IN ('r','v','m','f','p')
                AND n.nspname NOT IN ('pg_catalog','information_schema')
                AND NOT n.nspname LIKE 'pg_toast%'
                AND c.relname = requested.relation_name
                AND (
                  (requested.schema_name IS NOT NULL AND n.nspname = requested.schema_name)
                  OR (requested.schema_name IS NULL AND pg_catalog.pg_table_is_visible(c.oid))
                )
            ) AS v,
            (
              SELECT CASE
                WHEN c.relkind IN ('v','m','p') THEN c.relkind::text
                WHEN EXISTS (
                  SELECT 1
                  FROM pg_catalog.pg_inherits i
                  WHERE i.inhparent OPERATOR(pg_catalog.=) c.oid
                ) THEN 'h'
                ELSE c.relkind::text
              END
              FROM pg_catalog.pg_class c
              JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
              WHERE c.relkind IN ('r','v','m','f','p')
                AND NOT n.nspname LIKE 'pg_toast%'
                AND c.relname = requested.relation_name
                AND (
                  (requested.schema_name IS NOT NULL AND n.nspname = requested.schema_name)
                  OR (requested.schema_name IS NULL AND pg_catalog.pg_table_is_visible(c.oid))
                )
              LIMIT 1
            ) AS kind
            FROM requested
            ORDER BY requested.ordinal
            """);
        return sql.ToString();
    }

    internal static bool TryParseObjectName(
        string objectName,
        out string? schema,
        out string relation) =>
        PgCatalogObjectName.TryParse(objectName, out schema, out relation);

    internal static string BuildExistsSql(string? schema, string relation)
    {
        return BuildResolveSql(schema, relation);
    }

    private static string BuildResolveSql(string? schema, string relation)
    {
        string relLiteral = PgCatalogObjectName.EscapeLiteral(relation);
        StringBuilder sql = new();
        sql.Append(
            """
            SELECT EXISTS (
              SELECT 1
              FROM pg_catalog.pg_class c
              JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
              WHERE c.relkind IN ('r','v','m','f','p')
                AND n.nspname NOT IN ('pg_catalog','information_schema')
                AND NOT n.nspname LIKE 'pg_toast%'
                AND c.relname = '
            """);
        sql.Append(relLiteral);
        sql.Append("'");
        if (schema is not null)
        {
            sql.Append(CultureInfo.InvariantCulture, $" AND n.nspname = '{PgCatalogObjectName.EscapeLiteral(schema)}'");
        }
        else
        {
            sql.Append(" AND pg_catalog.pg_table_is_visible(c.oid)");
        }
        sql.Append(
            """
            ) AS v,
            (
              SELECT CASE
                WHEN c.relkind IN ('v','m','p') THEN c.relkind::text
                WHEN EXISTS (
                  SELECT 1
                  FROM pg_catalog.pg_inherits i
                  WHERE i.inhparent OPERATOR(pg_catalog.=) c.oid
                ) THEN 'h'
                ELSE c.relkind::text
              END
              FROM pg_catalog.pg_class c
              JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
              WHERE c.relkind IN ('r','v','m','f','p')
                AND NOT n.nspname LIKE 'pg_toast%'
                AND c.relname = '
            """);
        sql.Append(relLiteral);
        sql.Append("'");
        if (schema is not null)
        {
            sql.Append(CultureInfo.InvariantCulture, $" AND n.nspname = '{PgCatalogObjectName.EscapeLiteral(schema)}'");
        }
        else
        {
            sql.Append(" AND pg_catalog.pg_table_is_visible(c.oid)");
        }

        sql.Append(" LIMIT 1) AS kind");
        return sql.ToString();
    }

    private static bool IsUnsupportedRelationKind(string? kind) => kind is "v" or "m" or "p" or "h";

    private static SqlIr CloneIr(
        SqlIr source,
        IReadOnlyList<string> unresolvedObjects,
        IReadOnlyList<string>? riskCodes = null)
    {
        return new SqlIr(
            source.Dialect,
            source.StatementTypes,
            source.TablesRead,
            source.TablesWritten,
            source.ColumnsRead,
            source.ColumnsWritten,
            source.Functions,
            source.HasMultipleStatements,
            source.HasDynamicSql,
            unresolvedObjects,
            riskCodes ?? source.RiskCodes,
            source.NormalizedSql,
            source.Fingerprint,
            source.Operators,
            source.FunctionReferences,
            source.TypeReferences)
        {
            Int4ConstantProjectionCount = source.Int4ConstantProjectionCount,
        };
    }

    private static SqlAnalysis CreateEnrichedAnalysis(
        SqlAnalysis analysis,
        IReadOnlyList<string> unresolvedObjects,
        bool unsupportedRelation = false)
    {
        IReadOnlyList<string> risks = unsupportedRelation
            ? analysis.Ir.RiskCodes.Concat(["unsupported_construct"])
                .Distinct(StringComparer.Ordinal).OrderBy(static code => code, StringComparer.Ordinal).ToArray()
            : analysis.Ir.RiskCodes;
        SqlIr enrichedIr = CloneIr(analysis.Ir, unresolvedObjects, risks);
        return new SqlAnalysis(enrichedIr, analysis.IsParsable);
    }

    private sealed record ParsedObjectName(string OriginalName, string? Schema, string Relation)
    {
        public LookupIdentity Identity => LookupIdentity.Create(Schema, Relation);
    }

    private readonly record struct LookupIdentity(string? Schema, string Relation)
    {
        public static LookupIdentity Create(string? schema, string relation) =>
            new(schema, relation);
    }

}
