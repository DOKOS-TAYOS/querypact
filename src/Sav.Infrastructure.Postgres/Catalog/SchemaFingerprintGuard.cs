using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Sav.Application.Abstractions;
using Sav.Domain.Analysis;
using Sav.Domain.Errors;
using Sav.Domain.Targets;

namespace Sav.Infrastructure.Postgres.Catalog;

/// <summary>
/// Captures and re-checks <see cref="TargetSchemaFingerprint"/> on the pipeline-opened session
/// (TOCTOU guard). Does not call <see cref="IReadOnlySessionFactory"/>.
/// </summary>
public sealed class SchemaFingerprintGuard : ISchemaFingerprintGuard
{
    public static readonly TimeSpan DefaultMaxPipelineWallClock = TimeSpan.FromSeconds(30);

    private static readonly OracleScalarColumn[] DigestColumns =
    [
        new("v", OracleScalarKind.StringV),
    ];

    private readonly TimeSpan _maxPipelineWallClock;

    public SchemaFingerprintGuard(TimeSpan? maxPipelineWallClock = null)
    {
        _maxPipelineWallClock = maxPipelineWallClock ?? DefaultMaxPipelineWallClock;
        if (_maxPipelineWallClock <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(maxPipelineWallClock));
        }
    }

    public async Task<TargetSchemaFingerprint> CaptureBaselineAsync(
        IReadOnlySession session,
        TargetAlias target,
        SqlAnalysis analysis,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(session);
        ArgumentNullException.ThrowIfNull(target);
        ArgumentNullException.ThrowIfNull(analysis);
        return await ComputeFingerprintAsync(session, analysis, cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task EnsureUnchangedAsync(
        IReadOnlySession session,
        TargetAlias target,
        SqlAnalysis analysis,
        TargetSchemaFingerprint baseline,
        DateTimeOffset pipelineStartedUtc,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(session);
        ArgumentNullException.ThrowIfNull(target);
        ArgumentNullException.ThrowIfNull(analysis);
        ArgumentNullException.ThrowIfNull(baseline);

        if (DateTimeOffset.UtcNow - pipelineStartedUtc > _maxPipelineWallClock)
        {
            throw new SavException(
                SavErrorCode.SchemaChanged,
                "schema_changed: pipeline wall-clock threshold exceeded.");
        }

        TargetSchemaFingerprint current = await ComputeFingerprintAsync(
                session,
                analysis,
                cancellationToken)
            .ConfigureAwait(false);
        if (!string.Equals(current.Value, baseline.Value, StringComparison.Ordinal))
        {
            throw new SavException(
                SavErrorCode.SchemaChanged,
                "schema_changed: target schema fingerprint drifted.");
        }
    }

    private static async Task<TargetSchemaFingerprint> ComputeFingerprintAsync(
        IReadOnlySession session,
        SqlAnalysis analysis,
        CancellationToken cancellationToken)
    {
        string material = await CaptureMaterialAsync(session, analysis, cancellationToken)
            .ConfigureAwait(false);
        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(material));
        return new TargetSchemaFingerprint(Convert.ToHexString(hash).ToLowerInvariant());
    }

    private static async Task<string> CaptureMaterialAsync(
        IReadOnlySession session,
        SqlAnalysis analysis,
        CancellationToken cancellationToken)
    {
        SortedSet<string> relations = new(StringComparer.Ordinal);
        foreach (string name in analysis.Ir.TablesRead)
        {
            relations.Add(name);
        }

        foreach (string name in analysis.Ir.TablesWritten)
        {
            relations.Add(name);
        }

        if (relations.Count == 0)
        {
            return "empty";
        }

        List<string> digests = [];
        List<(string? Schema, string Relation)> safeRelations = [];
        foreach (string objectName in relations)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!PgCatalogObjectName.TryParse(objectName, out string? schema, out string relation))
            {
                digests.Add(objectName + ":unsafe");
                continue;
            }

            safeRelations.Add((schema, relation));
        }

        if (safeRelations.Count == 1)
        {
            (string? schema, string relation) = safeRelations[0];
            IReadOnlyList<OracleScalarRow> rows = await session
                .ExecuteReaderAsync(
                    BuildRelationDigestSql(schema, relation),
                    DigestColumns,
                    cancellationToken)
                .ConfigureAwait(false);
            string digest = rows.Count > 0 ? rows[0].StringV ?? string.Empty : string.Empty;
            digests.Add(
                string.Create(
                    CultureInfo.InvariantCulture,
                    $"{schema ?? "*"}.{relation}={digest}"));
        }
        else if (safeRelations.Count > 1)
        {
            IReadOnlyList<OracleScalarRow> rows = await session
                .ExecuteReaderAsync(BuildRelationDigestsSql(safeRelations), DigestColumns, cancellationToken)
                .ConfigureAwait(false);
            digests.AddRange(rows.Select(row => row.StringV ?? string.Empty));
        }

        digests.Sort(StringComparer.Ordinal);
        return string.Join("|", digests);
    }

    internal static string BuildRelationDigestSql(string? schema, string relation)
    {
        string lookupName = schema is null
            ? PgCatalogObjectName.QuoteIdentifier(relation)
            : PgCatalogObjectName.QuoteIdentifier(schema) + "." + PgCatalogObjectName.QuoteIdentifier(relation);
        string lookupLiteral = PgCatalogObjectName.EscapeLiteral(lookupName);

        return
            """
            SELECT COALESCE(
              c.oid::text || ':' || c.relkind::text || ':' ||
              COALESCE((
                SELECT string_agg(
                  a.attnum::text || ':' || a.attname || ':' ||
                  a.atttypid::text || ':' || a.atttypmod::text || ':' ||
                  a.attnotnull::text || ':' || a.attcollation::text || ':' ||
                  a.attidentity::text || ':' || a.attgenerated::text || ':' ||
                  COALESCE(pg_catalog.pg_get_expr(ad.adbin, ad.adrelid), ''),
                  ',' ORDER BY a.attnum)
                FROM pg_catalog.pg_attribute a
                LEFT JOIN pg_catalog.pg_attrdef ad
                  ON ad.adrelid = a.attrelid AND ad.adnum = a.attnum
                WHERE a.attrelid = c.oid
                  AND a.attnum > 0
                  AND NOT a.attisdropped
              ), '') || ':' ||
              COALESCE((
                SELECT string_agg(
                  con.contype::text || ':' ||
                  COALESCE(con.conkey::text, '') || ':' ||
                  con.confrelid::text || ':' ||
                  COALESCE(con.confkey::text, '') || ':' ||
                  pg_catalog.pg_get_constraintdef(con.oid, true),
                  ',' ORDER BY con.oid)
                FROM pg_catalog.pg_constraint con
                WHERE con.conrelid = c.oid
              ), '') || ':' ||
              COALESCE(
                CASE
                  WHEN c.relkind IN ('v','m') THEN pg_catalog.pg_get_viewdef(c.oid, true)
                  ELSE ''
                END,
                ''),
              '') AS v
            FROM pg_catalog.pg_class c
            WHERE c.oid = pg_catalog.to_regclass('
            """ + lookupLiteral + "')";
    }

    internal static string BuildRelationDigestsSql(IReadOnlyList<(string? Schema, string Relation)> relations)
    {
        StringBuilder sql = new();
        sql.Append(
            """
            WITH requested(schema_name, relation_name, lookup_name) AS (
              VALUES
            """);
        for (int i = 0; i < relations.Count; i++)
        {
            if (i > 0)
            {
                sql.AppendLine(",");
            }

            (string? schema, string relation) = relations[i];
            string lookupName = schema is null
                ? PgCatalogObjectName.QuoteIdentifier(relation)
                : PgCatalogObjectName.QuoteIdentifier(schema) + "." + PgCatalogObjectName.QuoteIdentifier(relation);
            sql.Append("    (");
            sql.Append(schema is null
                ? "NULL::text"
                : $"'{PgCatalogObjectName.EscapeLiteral(schema)}'::text");
            sql.Append(", '");
            sql.Append(PgCatalogObjectName.EscapeLiteral(relation));
            sql.Append("', '");
            sql.Append(PgCatalogObjectName.EscapeLiteral(lookupName));
            sql.Append("'::text)");
        }

        sql.AppendLine(")")
            .AppendLine("SELECT COALESCE(requested.schema_name, '*') || '.' || requested.relation_name || '=' ||")
            .AppendLine("  COALESCE((")
            .AppendLine("    SELECT c.oid::text || ':' || c.relkind::text || ':' ||")
            .AppendLine("      COALESCE((")
            .AppendLine("        SELECT string_agg(")
            .AppendLine("          a.attnum::text || ':' || a.attname || ':' ||")
            .AppendLine("          a.atttypid::text || ':' || a.atttypmod::text || ':' ||")
            .AppendLine("          a.attnotnull::text || ':' || a.attcollation::text || ':' ||")
            .AppendLine("          a.attidentity::text || ':' || a.attgenerated::text || ':' ||")
            .AppendLine("          COALESCE(pg_catalog.pg_get_expr(ad.adbin, ad.adrelid), ''),")
            .AppendLine("          ',' ORDER BY a.attnum)")
            .AppendLine("        FROM pg_catalog.pg_attribute a")
            .AppendLine("        LEFT JOIN pg_catalog.pg_attrdef ad")
            .AppendLine("          ON ad.adrelid = a.attrelid AND ad.adnum = a.attnum")
            .AppendLine("        WHERE a.attrelid = c.oid")
            .AppendLine("          AND a.attnum > 0")
            .AppendLine("          AND NOT a.attisdropped")
            .AppendLine("      ), '') || ':' ||")
            .AppendLine("      COALESCE((")
            .AppendLine("        SELECT string_agg(")
            .AppendLine("          con.contype::text || ':' ||")
            .AppendLine("          COALESCE(con.conkey::text, '') || ':' ||")
            .AppendLine("          con.confrelid::text || ':' ||")
            .AppendLine("          COALESCE(con.confkey::text, '') || ':' ||")
            .AppendLine("          pg_catalog.pg_get_constraintdef(con.oid, true),")
            .AppendLine("          ',' ORDER BY con.oid)")
            .AppendLine("        FROM pg_catalog.pg_constraint con")
            .AppendLine("        WHERE con.conrelid = c.oid")
            .AppendLine("      ), '') || ':' ||")
            .AppendLine("      COALESCE(")
            .AppendLine("        CASE")
            .AppendLine("          WHEN c.relkind IN ('v','m') THEN pg_catalog.pg_get_viewdef(c.oid, true)")
            .AppendLine("          ELSE ''")
            .AppendLine("        END,")
            .AppendLine("        '')")
            .AppendLine("    FROM pg_catalog.pg_class c")
            .AppendLine("    WHERE c.oid = pg_catalog.to_regclass(requested.lookup_name)")
            .AppendLine("  ), '') AS v")
            .AppendLine("FROM requested");
        return sql.ToString();
    }

}
