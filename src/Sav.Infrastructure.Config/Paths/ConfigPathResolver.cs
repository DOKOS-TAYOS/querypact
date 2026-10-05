using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using Microsoft.Win32.SafeHandles;
using Sav.Application.Abstractions;
using Sav.Domain.Errors;

namespace Sav.Infrastructure.Config.Paths;

public sealed class ConfigPathResolver : IConfigPathResolver
{
    private const uint OpenExisting = 3;
    private const uint FileFlagBackupSemantics = 0x02000000;
    private const uint FileShareReadWriteDelete = 0x00000007;

    private readonly string _configRootFull;

    public ConfigPathResolver(ConfigRootOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        string configured = string.IsNullOrWhiteSpace(options.ConfigRoot)
            ? Directory.GetCurrentDirectory()
            : options.ConfigRoot;
        _configRootFull = NormalizeDirectory(Path.GetFullPath(configured));
    }

    public string ResolveUnderConfigRoot(string relativeOrConfiguredPath)
    {
        if (string.IsNullOrWhiteSpace(relativeOrConfiguredPath))
        {
            throw CreatePathNotAllowed("Path is empty.");
        }

        if (relativeOrConfiguredPath.Contains('\0', StringComparison.Ordinal))
        {
            throw CreatePathNotAllowed("Path contains a null byte.");
        }

        string candidateFull;
        try
        {
            candidateFull = Path.IsPathRooted(relativeOrConfiguredPath)
                ? Path.GetFullPath(relativeOrConfiguredPath)
                : Path.GetFullPath(Path.Combine(_configRootFull, relativeOrConfiguredPath));
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            throw CreatePathNotAllowed("Path could not be normalized.");
        }

        if (!IsUnderConfigRoot(candidateFull))
        {
            throw CreatePathNotAllowed("Path escapes ConfigRoot.");
        }

        if (OperatingSystem.IsWindows())
        {
            RejectWindowsReparseOrFinalPathEscape(candidateFull);
        }
        else
        {
            RejectUnixSymlink(candidateFull);
        }

        return candidateFull;
    }

    private bool IsUnderConfigRoot(string fullPath)
    {
        string normalized = NormalizeDirectory(fullPath);
        StringComparison comparison = OperatingSystem.IsWindows()
            ? StringComparison.OrdinalIgnoreCase
            : StringComparison.Ordinal;
        if (string.Equals(normalized, _configRootFull, comparison))
        {
            return true;
        }

        string rootPrefix = Path.EndsInDirectorySeparator(_configRootFull)
            ? _configRootFull
            : _configRootFull + Path.DirectorySeparatorChar;
        return normalized.StartsWith(rootPrefix, comparison);
    }

    private static string NormalizeDirectory(string path)
    {
        string full = Path.GetFullPath(path);
        string filesystemRoot = Path.GetPathRoot(full) ?? string.Empty;
        string normalized = full.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        // Keep "/" and drive/UNC roots intact. Trimming C:\ to C: would make
        // path combination drive-relative; trimming "/" would make it empty.
        return normalized.Length < filesystemRoot.Length ? filesystemRoot : normalized;
    }

    /// <summary>
    /// Reject symbolic links at every component from ConfigRoot to the requested path.
    /// Checking only the final component misses files reached through a linked directory.
    /// </summary>
    private void RejectUnixSymlink(string candidateFull)
    {
        try
        {
            string current = _configRootFull;
            RejectLink(current);

            string relative = Path.GetRelativePath(_configRootFull, candidateFull);
            foreach (string component in relative.Split(
                         Path.DirectorySeparatorChar,
                         StringSplitOptions.RemoveEmptyEntries))
            {
                if (component == ".")
                {
                    continue;
                }

                current = Path.Combine(current, component);
                RejectLink(current);
            }
        }
        catch (SavException)
        {
            throw;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or PlatformNotSupportedException)
        {
            throw CreatePathNotAllowed("Path attributes could not be read.");
        }
    }

    private static void RejectLink(string path)
    {
        FileSystemInfo? link = File.ResolveLinkTarget(path, returnFinalTarget: false)
            ?? Directory.ResolveLinkTarget(path, returnFinalTarget: false);
        if (link is not null)
        {
            throw CreatePathNotAllowed("Path contains a symbolic link.");
        }
    }

    [SupportedOSPlatform("windows")]
    private void RejectWindowsReparseOrFinalPathEscape(string candidateFull)
    {
        try
        {
            if (!File.Exists(candidateFull) && !Directory.Exists(candidateFull))
            {
                return;
            }

            FileAttributes attributes = File.GetAttributes(candidateFull);
            if (attributes.HasFlag(FileAttributes.ReparsePoint))
            {
                throw CreatePathNotAllowed("Path is a reparse point.");
            }
        }
        catch (SavException)
        {
            throw;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw CreatePathNotAllowed("Path attributes could not be read.");
        }

        string? finalPath = TryGetFinalPathName(candidateFull);
        if (finalPath is null)
        {
            return;
        }

        if (!IsUnderConfigRoot(finalPath))
        {
            throw CreatePathNotAllowed("Final path escapes ConfigRoot.");
        }
    }

    [SupportedOSPlatform("windows")]
    private static string? TryGetFinalPathName(string path)
    {
        using SafeFileHandle handle = CreateFileW(
            path,
            dwDesiredAccess: 0,
            dwShareMode: FileShareReadWriteDelete,
            lpSecurityAttributes: IntPtr.Zero,
            dwCreationDisposition: OpenExisting,
            dwFlagsAndAttributes: FileFlagBackupSemantics,
            hTemplateFile: IntPtr.Zero);

        if (handle.IsInvalid)
        {
            return null;
        }

        StringBuilder buffer = new(1024);
        uint length = GetFinalPathNameByHandleW(handle, buffer, (uint)buffer.Capacity, 0);
        if (length == 0)
        {
            return null;
        }

        if (length > buffer.Capacity)
        {
            buffer.EnsureCapacity((int)length);
            length = GetFinalPathNameByHandleW(handle, buffer, (uint)buffer.Capacity, 0);
            if (length == 0)
            {
                return null;
            }
        }

        return Path.GetFullPath(NormalizeWindowsFinalPath(buffer.ToString()));
    }

    internal static string NormalizeWindowsFinalPath(string finalPath)
    {
        const string ExtendedUncPrefix = @"\\?\UNC\";
        if (finalPath.StartsWith(ExtendedUncPrefix, StringComparison.OrdinalIgnoreCase))
        {
            return @"\\" + finalPath[ExtendedUncPrefix.Length..];
        }

        const string ExtendedPrefix = @"\\?\";
        return finalPath.StartsWith(ExtendedPrefix, StringComparison.Ordinal)
            ? finalPath[ExtendedPrefix.Length..]
            : finalPath;
    }

    private static SavException CreatePathNotAllowed(string reason)
    {
        return new SavException(SavErrorCode.PathNotAllowed, $"path_not_allowed: {reason}");
    }

    [SupportedOSPlatform("windows")]
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern SafeFileHandle CreateFileW(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    [SupportedOSPlatform("windows")]
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern uint GetFinalPathNameByHandleW(
        SafeFileHandle hFile,
        StringBuilder lpszFilePath,
        uint cchFilePath,
        uint dwFlags);
}
