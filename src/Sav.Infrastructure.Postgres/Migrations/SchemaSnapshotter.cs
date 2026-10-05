using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Sav.Application.Abstractions;
using Sav.Domain.Contracts;
using Sav.Domain.Errors;
using Sav.Domain.Schema;
using Sav.Infrastructure.Postgres.Oracle;

namespace Sav.Infrastructure.Postgres.Migrations;

/// <summary>
/// Captures allow-listed catalog aggregates into <see cref="SchemaSnapshot"/> (ephemeral only).
/// </summary>
public sealed class SchemaSnapshotter
{
    /// <summary>
    /// Allow-listed catalog SQL forms used by the snapshotter (aggregate-only scalar egress).
    /// </summary>
    public static IReadOnlyList<string> AllowListedSqlTemplates { get; } =
    [
        CountsByRelkindTemplate,
        RelationAttributesAggTemplate,
        ConstraintDefinitionsAggTemplate,
    ];

    private const string CountsByRelkindTemplate =
        "SELECT c.relkind AS relkind, COUNT(*)::bigint AS v FROM pg_catalog.pg_class c "
        + "JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "
        + "WHERE n.nspname = {schema} AND c.relkind IN ('r','S','v','m','c','t','f','p') "
        + "GROUP BY c.relkind";

    private const string RelationAttributesAggTemplate =
        "SELECT json_build_object('relation', c.relname, 'relkind', c.relkind::text, 'attributes', "
        + "COALESCE(json_agg(json_build_object("
        + "'attnum', a.attnum, "
        + "'name', a.attname, "
        + "'type', a.atttypid, "
        + "'typmod', a.atttypmod, "
        + "'notnull', a.attnotnull, "
        + "'identity', a.attidentity, "
        + "'generated', a.attgenerated, "
        + "'collation', a.attcollation, "
        + "'default', COALESCE(pg_catalog.pg_get_expr(ad.adbin, ad.adrelid), '')"
        + ") ORDER BY a.attnum) FILTER (WHERE a.attnum IS NOT NULL), '[]'::json), 'definition', CASE WHEN c.relkind IN ('v','m') THEN pg_catalog.pg_get_viewdef(c.oid, true) ELSE NULL END)::text AS v "
        + "FROM pg_catalog.pg_class c "
        + "JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "
        + "LEFT JOIN pg_catalog.pg_attribute a ON a.attrelid = c.oid "
        + "AND a.attnum > 0 AND NOT a.attisdropped "
        + "LEFT JOIN pg_catalog.pg_attrdef ad ON ad.adrelid = a.attrelid AND ad.adnum = a.attnum "
        + "WHERE n.nspname = {schema} AND c.relkind IN ('r','v','m','S','f','p','c','t') "
        + "GROUP BY c.oid, c.relname, c.relkind";

    private const string ConstraintDefinitionsAggTemplate =
        "SELECT COALESCE(json_agg(json_build_object("
        + "'relation', COALESCE(c.relname, ''), "
        + "'name', con.conname, "
        + "'definition', pg_catalog.pg_get_constraintdef(con.oid, true), "
        + "'validated', con.convalidated, "
        + "'deferrable', con.condeferrable, "
        + "'deferred', con.condeferred"
        + ") ORDER BY COALESCE(c.relname, ''), con.conname)::text, '[]') AS v "
        + "FROM pg_catalog.pg_constraint con "
        + "JOIN pg_catalog.pg_namespace n ON n.oid = con.connamespace "
        + "LEFT JOIN pg_catalog.pg_class c ON c.oid = con.conrelid "
        + "WHERE n.nspname = {schema}";

    public async Task<SchemaSnapshot> CaptureAsync(
        EphemeralSession session,
        string schemaName,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(session);
        cancellationToken.ThrowIfCancellationRequested();

        string schema = RequireSafeIdent(schemaName);

        Dictionary<string, long> counts = new(StringComparer.Ordinal);
        IReadOnlyList<OracleScalarRow> countRows = await session
            .ExecuteReaderAsync(
                CountsByRelkindTemplate.Replace("{schema}", Literal(schema), StringComparison.Ordinal),
                [new OracleScalarColumn("relkind", OracleScalarKind.StringV), OracleSqlTemplate.LongVColumn],
                cancellationToken)
            .ConfigureAwait(false);
        foreach (OracleScalarRow row in countRows)
        {
            if (row.StringV is not string relkind || row.LongV is not long count
                || !SchemaInvariantRelkindVocabulary.IsSupported(relkind))
            {
                throw new SavException(SavErrorCode.QueryFailed, "query_failed: schema snapshot count.");
            }

            if (count > 0)
            {
                counts[relkind] = count;
            }
        }

        string relationAttributesSql = RelationAttributesAggTemplate
            .Replace("{schema}", Literal(schema), StringComparison.Ordinal);
        IReadOnlyList<OracleScalarRow> relationRows = await session
            .ExecuteReaderAsync(
                relationAttributesSql,
                [new OracleScalarColumn("v", OracleScalarKind.StringV)],
                cancellationToken)
            .ConfigureAwait(false);

        Dictionary<string, string> digests = new(StringComparer.Ordinal);
        Dictionary<string, string> relationKinds = new(StringComparer.Ordinal);
        foreach (OracleScalarRow row in relationRows)
        {
            (string relation, string relkind, string signature) = ParseRelationSignature(row.StringV);
            _ = RequireSafeIdent(relation);
            string key = schema + "." + relation;
            digests[key] = Sha256Hex(signature);
            relationKinds[key] = relkind;
        }

        string constraintAggSql = ConstraintDefinitionsAggTemplate
            .Replace("{schema}", Literal(schema), StringComparison.Ordinal);
        string constraintAgg = await ReadStringAsync(session, constraintAggSql, cancellationToken)
            .ConfigureAwait(false);

        Dictionary<string, bool> constraints = new(StringComparer.Ordinal);
        Dictionary<string, string> constraintDigests = new(StringComparer.Ordinal);
        foreach (ConstraintMetadata constraint in ParseConstraintMetadata(constraintAgg))
        {
            _ = RequireSafeIdent(constraint.Name);
            constraints[constraint.Name] = true;

            if (constraint.Relation.Length > 0)
            {
                _ = RequireSafeIdent(constraint.Relation);
            }

            string key = constraint.Relation.Length == 0
                ? constraint.Name
                : schema + "." + constraint.Relation + "." + constraint.Name;
            constraintDigests[key] = Sha256Hex(constraint.Signature);
        }

        return new SchemaSnapshot(
            schema,
            counts,
            digests,
            constraints,
            constraintDigests,
            relationKinds);
    }

    private static (string Relation, string Relkind, string Signature) ParseRelationSignature(string? json)
    {
        try
        {
            using JsonDocument document = JsonDocument.Parse(json ?? string.Empty);
            JsonElement root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object
                || !root.TryGetProperty("relation", out JsonElement relation)
                || relation.ValueKind != JsonValueKind.String
                || !root.TryGetProperty("relkind", out JsonElement relkind)
                || relkind.ValueKind != JsonValueKind.String
                || !root.TryGetProperty("attributes", out JsonElement attributes)
                || attributes.ValueKind != JsonValueKind.Array)
            {
                throw new JsonException();
            }

            string relationKind = relkind.GetString()!;
            if (!SchemaInvariantRelkindVocabulary.IsSupported(relationKind))
            {
                throw new JsonException();
            }

            List<string> attributeSignatures = [];
            foreach (JsonElement attribute in attributes.EnumerateArray())
            {
                if (attribute.ValueKind != JsonValueKind.Object
                    || !attribute.TryGetProperty("name", out JsonElement name)
                    || name.ValueKind != JsonValueKind.String)
                {
                    throw new JsonException();
                }

                string attributeName = name.GetString()!;
                _ = RequireSafeIdent(attributeName);
                attributeSignatures.Add(attribute.GetRawText());
            }

            string signature = "[" + string.Join(",", attributeSignatures) + "]";
            if (relationKind is "v" or "m")
            {
                if (!root.TryGetProperty("definition", out JsonElement definition)
                    || definition.ValueKind != JsonValueKind.String
                    || string.IsNullOrWhiteSpace(definition.GetString()))
                {
                    throw new JsonException();
                }

                signature += ":" + definition.GetString();
            }

            return (relation.GetString()!, relationKind, signature);
        }
        catch (JsonException)
        {
            throw new SavException(SavErrorCode.QueryFailed, "query_failed: schema snapshot relation aggregate.");
        }
    }

    private static IReadOnlyList<ConstraintMetadata> ParseConstraintMetadata(string json)
    {
        try
        {
            using JsonDocument document = JsonDocument.Parse(json);
            JsonElement root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Array)
            {
                throw new JsonException();
            }

            List<ConstraintMetadata> constraints = [];
            foreach (JsonElement item in root.EnumerateArray())
            {
                if (item.ValueKind != JsonValueKind.Object
                    || !item.TryGetProperty("relation", out JsonElement relation)
                    || relation.ValueKind != JsonValueKind.String
                    || !item.TryGetProperty("name", out JsonElement name)
                    || name.ValueKind != JsonValueKind.String)
                {
                    throw new JsonException();
                }

                constraints.Add(new ConstraintMetadata(
                    relation.GetString()!,
                    name.GetString()!,
                    item.GetRawText()));
            }

            return constraints;
        }
        catch (JsonException)
        {
            throw new SavException(SavErrorCode.QueryFailed, "query_failed: schema snapshot constraint aggregate.");
        }
    }

    private static async Task<string> ReadStringAsync(
        EphemeralSession session,
        string sql,
        CancellationToken cancellationToken)
    {
        IReadOnlyList<OracleScalarRow> rows = await session
            .ExecuteReaderAsync(
                sql,
                [new OracleScalarColumn("v", OracleScalarKind.StringV)],
                cancellationToken)
            .ConfigureAwait(false);

        if (rows.Count != 1)
        {
            throw new SavException(SavErrorCode.QueryFailed, "query_failed: schema snapshot aggregate.");
        }

        return rows[0].StringV ?? string.Empty;
    }

    private static string RequireSafeIdent(string identifier)
    {
        string[] allow = [identifier];
        _ = PgIdentifierGuard.ValidateAndQuote(identifier, allow);
        return identifier;
    }

    private static string Literal(string validatedIdent)
    {
        return "'" + validatedIdent.Replace("'", "''", StringComparison.Ordinal) + "'";
    }

    private static string Sha256Hex(string value)
    {
        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(value));
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private sealed record ConstraintMetadata(string Relation, string Name, string Signature);
}
