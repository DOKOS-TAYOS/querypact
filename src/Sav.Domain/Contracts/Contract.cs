using Sav.Domain.Policies;

namespace Sav.Domain.Contracts;

public sealed record Contract
{
    public Contract(
        string id,
        string version,
        IReadOnlyList<PropertySpec> requiredProperties,
        DisclosureProfile disclosure)
    {
        ArgumentNullException.ThrowIfNull(requiredProperties);
        ArgumentNullException.ThrowIfNull(disclosure);

        Id = id;
        Version = version;
        RequiredProperties = requiredProperties.ToArray();
        Disclosure = disclosure;
    }

    public string Id { get; }

    public string Version { get; }

    public IReadOnlyList<PropertySpec> RequiredProperties { get; }

    public DisclosureProfile Disclosure { get; }
}
