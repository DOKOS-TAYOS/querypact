using Sav.Application.Abstractions;
using Sav.Domain.Policies;

namespace Sav.Infrastructure.Storage.Tests.Attestations;

/// <summary>
/// Test-only identity redactor for HMAC/store parity (never used in Host DI).
/// </summary>
internal sealed class PassThroughTestRedactor : IRedactor
{
    public string RedactText(string value, DisclosureProfile profile) => value;

    public T RedactObject<T>(T value, DisclosureProfile profile) => value;
}
