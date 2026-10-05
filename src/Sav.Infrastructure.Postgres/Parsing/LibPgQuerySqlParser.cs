using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Google.Protobuf;
using PgSqlParser;
using Sav.Application.Abstractions;
using Sav.Domain.Analysis;

namespace Sav.Infrastructure.Postgres.Parsing;

/// <summary>
/// Production <see cref="ISqlParser"/> adapter over Chosen package <c>pgsqlparser</c> 1.0.0 (ADR 0002).
/// </summary>
public sealed class LibPgQuerySqlParser : ISqlParser
{
    public SqlParseResult Parse(string sql, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(sql);

        try
        {
            var parse = Parser.Parse(sql);
            if (parse.Error is not null || parse.Value is null)
            {
                return new SqlParseResult(
                    Success: false,
                    Ir: null,
                    ErrorCode: "sql_unparsable",
                    RedactedMessage: Redact(parse.Error?.Message));
            }

            cancellationToken.ThrowIfCancellationRequested();

            ParseResult value = parse.Value;
            if (value.Stmts.Count == 0)
            {
                return new SqlParseResult(
                    Success: false,
                    Ir: null,
                    ErrorCode: "sql_unparsable",
                    RedactedMessage: "redacted_error");
            }

            SqlIrMappedFacts facts = SqlIrMapper.Map(value);

            bool multiFromSplit = false;
            var split = Parser.SplitWithParser(sql);
            if (split.Error is null && split.Value is not null)
            {
                multiFromSplit = split.Value.Statements.Count > 1;
            }

            string? normalized = TryNormalize(sql, value);
            string fingerprint = normalized is null
                ? Sha256Hex(JsonFormatter.Default.Format(value))
                : Sha256Hex(normalized);

            SqlIr ir = new(
                dialect: "postgresql",
                statementTypes: facts.StatementTypes,
                tablesRead: facts.TablesRead,
                tablesWritten: facts.TablesWritten,
                columnsRead: facts.ColumnsRead,
                columnsWritten: facts.ColumnsWritten,
                functions: facts.Functions,
                hasMultipleStatements: facts.HasMultipleStatements || multiFromSplit,
                hasDynamicSql: facts.HasDynamicSql,
                unresolvedObjects: facts.UnresolvedObjects,
                riskCodes: facts.RiskCodes,
                normalizedSql: normalized ?? string.Empty,
                fingerprint: fingerprint,
                operators: facts.Operators,
                functionReferences: facts.FunctionReferences,
                typeReferences: facts.TypeReferences)
            {
                Int4ConstantProjectionCount = facts.Int4ConstantProjectionCount,
            };

            return new SqlParseResult(
                Success: true,
                Ir: ir,
                ErrorCode: null,
                RedactedMessage: null);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (DllNotFoundException)
        {
            return new SqlParseResult(
                Success: false,
                Ir: null,
                ErrorCode: "native_load_failed",
                RedactedMessage: "native_library_unavailable");
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return new SqlParseResult(
                Success: false,
                Ir: null,
                ErrorCode: "sql_unparsable",
                RedactedMessage: Redact(ex.GetType().Name));
        }
    }

    private static string? TryNormalize(string sql, ParseResult value)
    {
        var deparse = Parser.Deparse(value);
        if (deparse.Error is null && !string.IsNullOrWhiteSpace(deparse.Value))
        {
            return deparse.Value;
        }

        var normalize = Parser.Normalize(sql);
        if (normalize.Error is null && !string.IsNullOrWhiteSpace(normalize.Value))
        {
            return normalize.Value;
        }

        var utility = Parser.NormalizeUtility(sql);
        if (utility.Error is null && !string.IsNullOrWhiteSpace(utility.Value))
        {
            return utility.Value;
        }

        return null;
    }

    private static string Sha256Hex(string value)
    {
        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(value));
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private static string Redact(string? message)
    {
        if (string.IsNullOrWhiteSpace(message))
        {
            return "redacted_error";
        }

        string scrubbed = Regex.Replace(message, "'[^']*'", "'***'");
        scrubbed = Regex.Replace(scrubbed, "\"[^\"]*\"", "\"***\"");
        scrubbed = Regex.Replace(scrubbed, @"\b[\w.+-]+@[\w.-]+\b", "***");
        return scrubbed;
    }
}

public sealed record SqlIrMappedFacts(
    IReadOnlyList<string> StatementTypes,
    IReadOnlyList<string> TablesRead,
    IReadOnlyList<string> TablesWritten,
    IReadOnlyList<string> ColumnsRead,
    IReadOnlyList<string> ColumnsWritten,
    IReadOnlyList<string> Functions,
    IReadOnlyList<string> FunctionReferences,
    IReadOnlyList<string> Operators,
    bool HasMultipleStatements,
    bool HasDynamicSql,
    IReadOnlyList<string> UnresolvedObjects,
    IReadOnlyList<string> RiskCodes)
{
    public IReadOnlyList<string> TypeReferences { get; init; } = [];

    public int Int4ConstantProjectionCount { get; init; }
}
