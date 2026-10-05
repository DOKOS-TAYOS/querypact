using System.Reflection;
using Sav.Domain.Attestations;
using Sav.Domain.Decisions;
using Sav.Domain.Policies;
using Sav.Domain.Targets;

namespace Sav.Domain.Tests;

public sealed class FingerprintSeparationTests
{
    [Fact]
    public void TargetAlias_fingerprint_is_string_alias_binding_not_schema_type()
    {
        TargetAlias alias = new(Alias: "prod_ro", Fingerprint: "alias-binding-fp-1");
        PropertyInfo? fingerprintProperty = typeof(TargetAlias).GetProperty(nameof(TargetAlias.Fingerprint));

        Assert.NotNull(fingerprintProperty);
        Assert.Equal(typeof(string), fingerprintProperty!.PropertyType);
        Assert.IsType<string>(alias.Fingerprint);
    }

    [Fact]
    public void TargetSchemaFingerprint_is_distinct_type_from_alias_binding_string()
    {
        TargetSchemaFingerprint schemaFp = new(Value: "schema-fp-1");
        TargetAlias alias = new(Alias: "prod_ro", Fingerprint: "alias-binding-fp-1");

        Assert.NotEqual(alias.Fingerprint, schemaFp.Value);
        Assert.IsType<TargetSchemaFingerprint>(schemaFp);
    }

    [Fact]
    public void Attestation_carries_target_alias_fingerprint_string_not_schema_fingerprint()
    {
        Type attestationType = typeof(Attestation);
        PropertyInfo? aliasFpProp = attestationType.GetProperty(nameof(Attestation.TargetAliasFingerprint));
        Assert.NotNull(aliasFpProp);
        Assert.Equal(typeof(string), aliasFpProp!.PropertyType);
        Assert.Null(attestationType.GetProperty("TargetSchemaFingerprint"));
        Assert.Null(attestationType.GetProperty("SchemaFingerprint"));
    }

    [Fact]
    public void Can_construct_attestation_with_alias_fingerprint_only()
    {
        StructuralSqlIr ir = new(
            "postgresql",
            ["Select"],
            [],
            [],
            [],
            [],
            [],
            false,
            false,
            [],
            []);

        Attestation attestation = new(
            "1",
            "att-1",
            "sql",
            "contract",
            "policy",
            "0.0.1-stub",
            "alias-binding-fp-1",
            AttestationDecision.Deny,
            new AttestationAnalysis(ir, IsParsable: false),
            null,
            [],
            new DisclosureProfile("strict", false, false, false, false),
            DateTimeOffset.UnixEpoch,
            "hmac");

        Assert.Equal("alias-binding-fp-1", attestation.TargetAliasFingerprint);
    }
}
