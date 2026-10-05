using Sav.Application.Abstractions;
using Sav.Domain.Policies;

namespace Sav.Security.Tests.Helpers;

/// <summary>
/// Test-only identity redactor (never used in Host DI).
/// </summary>
internal sealed class PassThroughTestRedactor : IRedactor
{
    public string RedactText(string value, DisclosureProfile profile) => value;

    public T RedactObject<T>(T value, DisclosureProfile profile) => value;
}
