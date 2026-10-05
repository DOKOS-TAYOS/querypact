using Sav.Domain.Decisions;
using Sav.Domain.Plans;
using Sav.Domain.Policies;
using Sav.Domain.Properties;

namespace Sav.Domain.Attestations;

public sealed record Attestation
{
    public Attestation(
        string schemaVersion,
        string id,
        string sqlHash,
        string contractHash,
        string policyHash,
        string savVersion,
        string targetAliasFingerprint,
        AttestationDecision decision,
        AttestationAnalysis analysis,
        PlanSummary? planSummary,
        IReadOnlyList<PropertyResult> properties,
        DisclosureProfile effectiveDisclosure,
        DateTimeOffset timestamp,
        string hmacSha256Base64)
    {
        ArgumentNullException.ThrowIfNull(properties);
        ArgumentNullException.ThrowIfNull(effectiveDisclosure);
        ArgumentNullException.ThrowIfNull(analysis);
        SchemaVersion = schemaVersion;
        Id = id;
        SqlHash = sqlHash;
        ContractHash = contractHash;
        PolicyHash = policyHash;
        SavVersion = savVersion;
        TargetAliasFingerprint = targetAliasFingerprint;
        Decision = decision;
        Analysis = analysis;
        PlanSummary = planSummary;
        Properties = properties.ToArray();
        EffectiveDisclosure = effectiveDisclosure;
        Timestamp = timestamp;
        HmacSha256Base64 = hmacSha256Base64;
    }

    public string SchemaVersion { get; }

    public string Id { get; }

    public string SqlHash { get; }

    public string ContractHash { get; }

    public string PolicyHash { get; }

    public string SavVersion { get; }

    public string TargetAliasFingerprint { get; }

    public AttestationDecision Decision { get; }

    public AttestationAnalysis Analysis { get; }

    public PlanSummary? PlanSummary { get; }

    public IReadOnlyList<PropertyResult> Properties { get; }

    public DisclosureProfile EffectiveDisclosure { get; }

    public DateTimeOffset Timestamp { get; }

    public string HmacSha256Base64 { get; }
}
