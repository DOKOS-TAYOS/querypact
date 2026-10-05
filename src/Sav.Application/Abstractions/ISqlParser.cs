namespace Sav.Application.Abstractions;

public interface ISqlParser
{
    /// <summary>
    /// Synchronous parse. <paramref name="cancellationToken"/> is best-effort only for native
    /// wrappers that cannot cooperatively cancel mid-parse (PARSE-CT / ADR 0002).
    /// </summary>
    SqlParseResult Parse(string sql, CancellationToken cancellationToken);
}
