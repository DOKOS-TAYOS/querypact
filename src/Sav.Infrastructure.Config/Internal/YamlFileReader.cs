using Sav.Domain.Errors;

namespace Sav.Infrastructure.Config.Internal;

internal static class YamlFileReader
{
    public static string ReadText(string path, string errorCode)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            throw new SavException(errorCode, $"{errorCode}: Path is empty.");
        }

        try
        {
            return File.ReadAllText(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or DirectoryNotFoundException)
        {
            // Never include file body contents in the message.
            throw new SavException(errorCode, $"{errorCode}: File could not be read.");
        }
    }
}
