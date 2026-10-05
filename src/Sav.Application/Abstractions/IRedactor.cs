using Sav.Domain.Policies;

namespace Sav.Application.Abstractions;

public interface IRedactor
{
    string RedactText(string value, DisclosureProfile profile);

    /// <summary>
    /// Pure function: returns a new instance; never mutates the input.
    /// </summary>
    T RedactObject<T>(T value, DisclosureProfile profile);
}
