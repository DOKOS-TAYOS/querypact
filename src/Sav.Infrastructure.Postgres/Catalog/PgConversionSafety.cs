using System.Text;
using Sav.Application.Abstractions;
using Sav.Domain.Analysis;

namespace Sav.Infrastructure.Postgres.Catalog;

/// <summary>
/// Conservative conversion gate over catalog metadata only. Never asks PostgreSQL to parse,
/// plan, or execute the proposed SQL: even planning can invoke conversion routines.
/// </summary>
internal static class PgConversionSafety
{
    private static readonly OracleScalarColumn[] Columns = [new("v", OracleScalarKind.BoolV)];

    public static async Task<bool> IsSafeAsync(
        IReadOnlyList<SqlAnalysis> analyses,
        IReadOnlySession session,
        CancellationToken cancellationToken)
    {
        List<Request> requests = [];
        foreach (SqlAnalysis analysis in analyses.Where(static analysis => analysis.IsParsable))
        {
            if (!AddRequests(analysis.Ir.TypeReferences, "type", requests) ||
                !AddRequests(analysis.Ir.TablesRead.Concat(analysis.Ir.TablesWritten), "relation", requests) ||
                !AddRequests(analysis.Ir.FunctionReferences, "function", requests) ||
                !AddRequests(analysis.Ir.Operators, "operator", requests))
            {
                return false;
            }
        }

        if (analyses.All(static analysis => !analysis.IsParsable))
        {
            return true;
        }

        // Pair wrappers introduce EXCEPT coercions. Only matching all-int4 projections
        // establish that neither the queries nor the pair need any conversion path.
        bool noCastPath = requests.Count == 0 && analyses.All(static analysis => analysis.IsParsable &&
            analysis.Ir.Int4ConstantProjectionCount > 0 && !analysis.Ir.HasMultipleStatements &&
            !analysis.Ir.HasDynamicSql && analysis.Ir.RiskCodes.Count == 0) &&
            analyses.Select(static analysis => analysis.Ir.Int4ConstantProjectionCount).Distinct().Count() == 1;
        if (noCastPath)
        {
            requests.Add(new Request("type", "pg_catalog", "int4", false));
        }

        IReadOnlyList<OracleScalarRow> rows = await session.ExecuteReaderAsync(
            BuildSql(requests.Distinct().ToArray(), checkCastPaths: !noCastPath), Columns, cancellationToken).ConfigureAwait(false);
        // Missing, null, or duplicate results cannot establish conversion safety.
        return rows.Count == 1 && rows[0].BoolV == true;
    }

    private static bool AddRequests(IEnumerable<string> names, string kind, List<Request> requests)
    {
        foreach (string reference in names)
        {
            bool array = kind == "type" && reference.EndsWith("[]", StringComparison.Ordinal);
            string name = array ? reference[..^2] : reference;
            // Function references already carry PostgreSQL identifier normalization.
            // The catalog name parser trims input; do not let it rebind a delimited name.
            if (kind == "function" && !string.Equals(name, name.Trim(), StringComparison.Ordinal))
            {
                return false;
            }

            string? schema;
            string item;
            if (kind == "operator")
            {
                string[] parts = name.Split('.');
                if (parts.Length is < 1 or > 2 || parts.Any(string.IsNullOrWhiteSpace))
                {
                    return false;
                }

                schema = parts.Length == 2 ? parts[0] : null;
                item = parts[^1];
            }
            else if (!PgCatalogObjectName.TryParse(name, out schema, out item))
            {
                return false;
            }

            requests.Add(new Request(kind, schema, item, array));
        }

        return true;
    }

    private static string BuildSql(IReadOnlyList<Request> requests, bool checkCastPaths)
    {
        StringBuilder sql = new("WITH requested(kind, schema_name, object_name, is_array) AS (\n");
        if (requests.Count == 0)
        {
            sql.AppendLine("SELECT NULL::pg_catalog.text, NULL::pg_catalog.name, NULL::pg_catalog.name, false WHERE false");
        }
        else
        {
            sql.AppendLine("VALUES");
            for (int index = 0; index < requests.Count; index++)
            {
                Request request = requests[index];
                if (index > 0)
                {
                    sql.AppendLine(",");
                }

                sql.Append("('").Append(request.Kind).Append("'::pg_catalog.text, ");
                sql.Append(request.Schema is null ? "NULL::pg_catalog.name" : Literal(request.Schema));
                sql.Append(", ").Append(Literal(request.Name));
                sql.Append(request.Array ? ", true)" : ", false)");
            }
        }

        sql.AppendLine(
            """
            ), trusted_routines AS (
              SELECT p.oid FROM pg_catalog.pg_proc p
              JOIN pg_catalog.pg_namespace n ON n.oid OPERATOR(pg_catalog.=) p.pronamespace
              WHERE p.oid OPERATOR(pg_catalog.<) 16384::pg_catalog.oid
                AND n.nspname OPERATOR(pg_catalog.=) 'pg_catalog'::pg_catalog.name
            ), trusted_types AS (
              SELECT t.oid FROM pg_catalog.pg_type t
              JOIN pg_catalog.pg_namespace n ON n.oid OPERATOR(pg_catalog.=) t.typnamespace
              WHERE t.oid OPERATOR(pg_catalog.<) 16384::pg_catalog.oid
            """);
        if (!checkCastPaths)
        {
            // Integer parse nodes refer to the fixed bootstrap int4 OID, not a search-path name.
            sql.AppendLine("    AND t.oid OPERATOR(pg_catalog.=) 23::pg_catalog.oid");
        }

        sql.AppendLine(
            """
                AND n.nspname OPERATOR(pg_catalog.=) 'pg_catalog'::pg_catalog.name
                AND NOT (t.typtype OPERATOR(pg_catalog.=) 'd'::pg_catalog."char")
                AND EXISTS (SELECT 1 FROM trusted_routines p WHERE p.oid OPERATOR(pg_catalog.=) t.typinput)
                AND EXISTS (SELECT 1 FROM trusted_routines p WHERE p.oid OPERATOR(pg_catalog.=) t.typoutput)
                AND (t.typmodin OPERATOR(pg_catalog.=) 0::pg_catalog.oid OR
                     EXISTS (SELECT 1 FROM trusted_routines p WHERE p.oid OPERATOR(pg_catalog.=) t.typmodin))
                AND (t.typmodout OPERATOR(pg_catalog.=) 0::pg_catalog.oid OR
                     EXISTS (SELECT 1 FROM trusted_routines p WHERE p.oid OPERATOR(pg_catalog.=) t.typmodout))
                AND (t.typelem OPERATOR(pg_catalog.=) 0::pg_catalog.oid OR
                     t.typelem OPERATOR(pg_catalog.<) 16384::pg_catalog.oid)
            ), named_types AS (
              SELECT r.kind, r.schema_name, r.object_name, r.is_array,
                     CASE WHEN r.is_array THEN t.typarray ELSE t.oid END AS oid
              FROM requested r
              JOIN pg_catalog.pg_type t ON t.typname OPERATOR(pg_catalog.=) r.object_name
              JOIN pg_catalog.pg_namespace n ON n.oid OPERATOR(pg_catalog.=) t.typnamespace
              WHERE (r.kind OPERATOR(pg_catalog.=) 'type'::pg_catalog.text OR
                     r.kind OPERATOR(pg_catalog.=) 'function'::pg_catalog.text)
                AND ((r.schema_name IS NULL AND pg_catalog.pg_type_is_visible(t.oid)) OR
                     n.nspname OPERATOR(pg_catalog.=) r.schema_name)
            ), roots AS (
              SELECT oid FROM named_types
            """);
        // Proven literal projections have no relation/routine/operator dependencies.
        if (checkCastPaths)
        {
            sql.AppendLine(
            """
              UNION ALL
              SELECT a.atttypid FROM requested r
              JOIN pg_catalog.pg_class c ON c.relname OPERATOR(pg_catalog.=) r.object_name
              JOIN pg_catalog.pg_namespace n ON n.oid OPERATOR(pg_catalog.=) c.relnamespace
              JOIN pg_catalog.pg_attribute a ON a.attrelid OPERATOR(pg_catalog.=) c.oid
              WHERE r.kind OPERATOR(pg_catalog.=) 'relation'::pg_catalog.text
                AND a.attnum OPERATOR(pg_catalog.>) 0::pg_catalog.int2 AND NOT a.attisdropped
                AND ((r.schema_name IS NULL AND pg_catalog.pg_table_is_visible(c.oid)) OR
                     n.nspname OPERATOR(pg_catalog.=) r.schema_name)
              UNION ALL
              SELECT signature.oid FROM requested r
              JOIN pg_catalog.pg_proc p ON p.proname OPERATOR(pg_catalog.=) r.object_name
              JOIN pg_catalog.pg_namespace n ON n.oid OPERATOR(pg_catalog.=) p.pronamespace
              CROSS JOIN LATERAL pg_catalog.unnest(
                ARRAY[p.prorettype] OPERATOR(pg_catalog.||)
                p.proargtypes::pg_catalog.oid[] OPERATOR(pg_catalog.||)
                COALESCE(p.proallargtypes, ARRAY[]::pg_catalog.oid[])) signature(oid)
              WHERE r.kind OPERATOR(pg_catalog.=) 'function'::pg_catalog.text
                AND ((r.schema_name IS NULL AND pg_catalog.pg_function_is_visible(p.oid)) OR
                     n.nspname OPERATOR(pg_catalog.=) r.schema_name)
              UNION ALL
              SELECT signature.oid FROM requested r
              JOIN pg_catalog.pg_operator o ON o.oprname OPERATOR(pg_catalog.=) r.object_name
              JOIN pg_catalog.pg_namespace n ON n.oid OPERATOR(pg_catalog.=) o.oprnamespace
              CROSS JOIN LATERAL pg_catalog.unnest(ARRAY[o.oprleft, o.oprright, o.oprresult]) signature(oid)
              WHERE r.kind OPERATOR(pg_catalog.=) 'operator'::pg_catalog.text
                AND NOT (signature.oid OPERATOR(pg_catalog.=) 0::pg_catalog.oid)
                AND ((r.schema_name IS NULL AND pg_catalog.pg_operator_is_visible(o.oid)) OR
                     n.nspname OPERATOR(pg_catalog.=) r.schema_name)
            """);
        }

        sql.AppendLine(
            """
            )
            SELECT NOT EXISTS (
              SELECT 1 FROM requested r
              WHERE r.kind OPERATOR(pg_catalog.=) 'type'::pg_catalog.text
                AND NOT EXISTS (
                  SELECT 1 FROM named_types t
                  WHERE t.kind OPERATOR(pg_catalog.=) r.kind
                    AND t.object_name OPERATOR(pg_catalog.=) r.object_name
                    AND t.is_array OPERATOR(pg_catalog.=) r.is_array
                    AND ((t.schema_name IS NULL AND r.schema_name IS NULL) OR
                         t.schema_name OPERATOR(pg_catalog.=) r.schema_name)
                )
            ) AND NOT EXISTS (
              SELECT 1 FROM roots r WHERE NOT EXISTS (
                SELECT 1 FROM trusted_types t WHERE t.oid OPERATOR(pg_catalog.=) r.oid
              )
            )
            """);
        if (checkCastPaths)
        {
            sql.AppendLine(
            """
            AND NOT EXISTS (
              -- The raw parse tree does not identify selected implicit/assignment casts.
              -- With custom type roots excluded, only bootstrap-to-bootstrap paths remain.
              -- Reject added/replaced paths conservatively, including same-type typmod casts.
              SELECT 1 FROM pg_catalog.pg_cast c
              WHERE c.castsource OPERATOR(pg_catalog.<) 16384::pg_catalog.oid
                AND c.casttarget OPERATOR(pg_catalog.<) 16384::pg_catalog.oid
                AND NOT (
                  c.oid OPERATOR(pg_catalog.<) 16384::pg_catalog.oid
                  AND (c.castmethod OPERATOR(pg_catalog.=) 'b'::pg_catalog."char" OR
                       (c.castmethod OPERATOR(pg_catalog.=) 'i'::pg_catalog."char" AND
                        EXISTS (SELECT 1 FROM trusted_types t WHERE t.oid OPERATOR(pg_catalog.=) c.castsource) AND
                        EXISTS (SELECT 1 FROM trusted_types t WHERE t.oid OPERATOR(pg_catalog.=) c.casttarget)) OR
                       (c.castmethod OPERATOR(pg_catalog.=) 'f'::pg_catalog."char" AND
                        EXISTS (SELECT 1 FROM trusted_routines p WHERE p.oid OPERATOR(pg_catalog.=) c.castfunc)))
                )
            )
            """);
        }

        sql.AppendLine(" AS v");
        return sql.ToString();
    }

    private static string Literal(string value) => $"'{PgCatalogObjectName.EscapeLiteral(value)}'::pg_catalog.name";

    private sealed record Request(string Kind, string? Schema, string Name, bool Array);
}
