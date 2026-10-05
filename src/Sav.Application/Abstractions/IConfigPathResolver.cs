namespace Sav.Application.Abstractions;

/// <summary>
/// Resolves operator-configured paths under <c>Sav:ConfigRoot</c> (confused-deputy / LFI control).
/// </summary>
public interface IConfigPathResolver
{
    /// <summary>
    /// Resolve <paramref name="relativeOrConfiguredPath"/> under ConfigRoot.
    /// Rejects null/empty, rooted paths outside root, and <c>..</c> escapes.
    /// Typed failure: <c>path_not_allowed</c>.
    /// </summary>
    string ResolveUnderConfigRoot(string relativeOrConfiguredPath);
}
