using System.Text.Json.Nodes;
using Sav.Application.Attestations;
using Sav.Domain.Attestations;
using Sav.Domain.Decisions;
using Sav.Domain.Errors;
using Sav.Domain.Policies;
using Sav.Domain.Properties;
using Sav.Infrastructure.Storage.Attestations;

namespace Sav.Infrastructure.Storage.Tests.Attestations;

public sealed class FileAttestationStoreTests
{
    private static readonly byte[] Key = Enumerable.Repeat((byte)0x55, 32).ToArray();

    [Fact]
    public async Task Save_then_get_round_trips_valid_attestation()
    {
        using TempStoreRoot root = TempStoreRoot.Create();
        FileAttestationStore store = CreateStore(root.Path);
        Attestation created = CreateSigned("att-round-1");

        string id = await store.SaveAsync(created, CancellationToken.None);
        Attestation? loaded = await store.GetAsync(id, CancellationToken.None);

        Assert.Equal(created.Id, id);
        Assert.NotNull(loaded);
        Assert.Equal(created.HmacSha256Base64, loaded.HmacSha256Base64);
        Assert.Equal(created.SqlHash, loaded.SqlHash);
        Assert.True(File.Exists(Path.Combine(root.Path, id + ".json")));
    }

    [Fact]
    public void Constructor_rejects_hmac_key_shorter_than_32_bytes()
    {
        using TempStoreRoot root = TempStoreRoot.Create();
        byte[] weak = Enumerable.Repeat((byte)0x55, 31).ToArray();

        ArgumentException ex = Assert.Throws<ArgumentException>(
            () => new FileAttestationStore(root.Path, new AttestationHmac(), weak));

        Assert.Contains("32", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void VerifyIntegrity_rejects_hmac_key_shorter_than_32_bytes()
    {
        Attestation created = CreateSigned("att-weak-key");
        byte[] weak = Enumerable.Repeat((byte)0x55, 31).ToArray();

        Assert.False(AttestationFactory.VerifyIntegrity(created, new AttestationHmac(), weak));
    }

    [Fact]
    public async Task Get_missing_returns_null()
    {
        using TempStoreRoot root = TempStoreRoot.Create();
        FileAttestationStore store = CreateStore(root.Path);

        Attestation? loaded = await store.GetAsync("missing-id", CancellationToken.None);
        Assert.Null(loaded);
    }

    [Fact]
    public async Task Get_rejects_invalid_id_before_filesystem_probe()
    {
        using TempStoreRoot root = TempStoreRoot.Create();
        FileAttestationStore store = CreateStore(root.Path);
        int filesBefore = Directory.GetFiles(root.Path).Length;

        SavException ex = await Assert.ThrowsAsync<SavException>(
            () => store.GetAsync("../etc/passwd", CancellationToken.None));

        Assert.Equal(SavErrorCode.AttestationIdInvalid, ex.Code);
        Assert.Equal(filesBefore, Directory.GetFiles(root.Path).Length);
        Assert.False(File.Exists(Path.Combine(root.Path, "..", "etc", "passwd")));
    }

    [Fact]
    public async Task Save_rejects_invalid_id()
    {
        using TempStoreRoot root = TempStoreRoot.Create();
        FileAttestationStore store = CreateStore(root.Path);
        Attestation bad = CreateSigned("../escape");

        SavException ex = await Assert.ThrowsAsync<SavException>(
            () => store.SaveAsync(bad, CancellationToken.None));
        Assert.Equal(SavErrorCode.AttestationIdInvalid, ex.Code);
    }

    [Fact]
    public async Task Get_throws_integrity_failure_on_tampered_file()
    {
        using TempStoreRoot root = TempStoreRoot.Create();
        FileAttestationStore store = CreateStore(root.Path);
        Attestation created = CreateSigned("att-tamper-1");
        await store.SaveAsync(created, CancellationToken.None);

        string path = Path.Combine(root.Path, created.Id + ".json");
        string json = await File.ReadAllTextAsync(path);
        string tampered = json.Replace(created.SqlHash, "deadbeef", StringComparison.Ordinal);
        await File.WriteAllTextAsync(path, tampered);

        SavException ex = await Assert.ThrowsAsync<SavException>(
            () => store.GetAsync(created.Id, CancellationToken.None));
        Assert.Equal(SavErrorCode.AttestationIntegrityFailure, ex.Code);
    }

    [Theory]
    [InlineData("schemaVersion")]
    [InlineData("id")]
    [InlineData("sqlHash")]
    [InlineData("contractHash")]
    [InlineData("policyHash")]
    [InlineData("savVersion")]
    [InlineData("targetAliasFingerprint")]
    [InlineData("decision")]
    [InlineData("analysis")]
    [InlineData("properties")]
    [InlineData("effectiveDisclosure")]
    [InlineData("hmacSha256Base64")]
    public async Task Get_rejects_explicit_null_required_fields_with_typed_integrity_error(string property)
    {
        using TempStoreRoot root = TempStoreRoot.Create();
        FileAttestationStore store = CreateStore(root.Path);
        Attestation created = CreateSigned("att-null-fields");
        await store.SaveAsync(created, CancellationToken.None);

        string path = Path.Combine(root.Path, created.Id + ".json");
        JsonObject record = JsonNode.Parse(await File.ReadAllTextAsync(path))!.AsObject();
        record[property] = null;
        await File.WriteAllTextAsync(path, record.ToJsonString());

        SavException ex = await Assert.ThrowsAsync<SavException>(
            () => store.GetAsync(created.Id, CancellationToken.None));
        Assert.Equal(SavErrorCode.AttestationIntegrityFailure, ex.Code);
        Assert.DoesNotContain(created.SqlHash, ex.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("analysis")]
    [InlineData("effectiveDisclosure")]
    [InlineData("hmacSha256Base64")]
    [InlineData("id")]
    public async Task Get_rejects_missing_required_fields_with_typed_integrity_error(string property)
    {
        using TempStoreRoot root = TempStoreRoot.Create();
        FileAttestationStore store = CreateStore(root.Path);
        Attestation created = CreateSigned("att-missing-fields");
        await store.SaveAsync(created, CancellationToken.None);

        string path = Path.Combine(root.Path, created.Id + ".json");
        JsonObject record = JsonNode.Parse(await File.ReadAllTextAsync(path))!.AsObject();
        Assert.True(record.Remove(property));
        await File.WriteAllTextAsync(path, record.ToJsonString());

        SavException ex = await Assert.ThrowsAsync<SavException>(
            () => store.GetAsync(created.Id, CancellationToken.None));
        Assert.Equal(SavErrorCode.AttestationIntegrityFailure, ex.Code);
    }

    [Fact]
    public async Task Get_rejects_null_nested_analysis_ir()
    {
        using TempStoreRoot root = TempStoreRoot.Create();
        FileAttestationStore store = CreateStore(root.Path);
        Attestation created = CreateSigned("att-null-nested");
        await store.SaveAsync(created, CancellationToken.None);

        string path = Path.Combine(root.Path, created.Id + ".json");
        JsonObject record = JsonNode.Parse(await File.ReadAllTextAsync(path))!.AsObject();
        record["analysis"]!["ir"] = null;
        await File.WriteAllTextAsync(path, record.ToJsonString());

        SavException ex = await Assert.ThrowsAsync<SavException>(
            () => store.GetAsync(created.Id, CancellationToken.None));
        Assert.Equal(SavErrorCode.AttestationIntegrityFailure, ex.Code);
    }

    [Fact]
    public async Task Get_rejects_null_property_result()
    {
        using TempStoreRoot root = TempStoreRoot.Create();
        FileAttestationStore store = CreateStore(root.Path);
        Attestation created = CreateSigned("att-null-property");
        await store.SaveAsync(created, CancellationToken.None);

        string path = Path.Combine(root.Path, created.Id + ".json");
        JsonObject record = JsonNode.Parse(await File.ReadAllTextAsync(path))!.AsObject();
        record["properties"]!.AsArray()[0] = null;
        await File.WriteAllTextAsync(path, record.ToJsonString());

        SavException ex = await Assert.ThrowsAsync<SavException>(
            () => store.GetAsync(created.Id, CancellationToken.None));
        Assert.Equal(SavErrorCode.AttestationIntegrityFailure, ex.Code);
    }

    [Fact]
    public async Task Get_normalizes_invalid_json_and_does_not_echo_corrupted_content()
    {
        using TempStoreRoot root = TempStoreRoot.Create();
        FileAttestationStore store = CreateStore(root.Path);
        Attestation created = CreateSigned("att-invalid-json");
        await store.SaveAsync(created, CancellationToken.None);

        const string corrupt = "{not-json-and-secret-value";
        await File.WriteAllTextAsync(Path.Combine(root.Path, created.Id + ".json"), corrupt);

        SavException ex = await Assert.ThrowsAsync<SavException>(
            () => store.GetAsync(created.Id, CancellationToken.None));
        Assert.Equal(SavErrorCode.AttestationIntegrityFailure, ex.Code);
        Assert.DoesNotContain(corrupt, ex.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("includePlanSummary")]
    [InlineData("includeObjectNames")]
    [InlineData("includeTimings")]
    [InlineData("includeRowCounts")]
    public async Task Get_rejects_missing_false_disclosure_flags_even_when_hmac_would_match(string field)
    {
        using TempStoreRoot root = TempStoreRoot.Create();
        FileAttestationStore store = CreateStore(root.Path);
        Attestation created = CreateSigned("att-missing-default");
        await store.SaveAsync(created, CancellationToken.None);

        string path = Path.Combine(root.Path, created.Id + ".json");
        JsonObject record = JsonNode.Parse(await File.ReadAllTextAsync(path))!.AsObject();
        Assert.True(record["effectiveDisclosure"]!.AsObject().Remove(field));
        await File.WriteAllTextAsync(path, record.ToJsonString());

        SavException ex = await Assert.ThrowsAsync<SavException>(
            () => store.GetAsync(created.Id, CancellationToken.None));
        Assert.Equal(SavErrorCode.AttestationIntegrityFailure, ex.Code);
    }

    [Theory]
    [InlineData("timestamp")]
    [InlineData("planSummary")]
    public async Task Get_rejects_omitted_value_or_optional_fields_in_persisted_shape(string field)
    {
        using TempStoreRoot root = TempStoreRoot.Create();
        FileAttestationStore store = CreateStore(root.Path);
        Attestation created = CreateSigned("att-omitted-shape");
        await store.SaveAsync(created, CancellationToken.None);

        string path = Path.Combine(root.Path, created.Id + ".json");
        JsonObject record = JsonNode.Parse(await File.ReadAllTextAsync(path))!.AsObject();
        Assert.True(record.Remove(field));
        await File.WriteAllTextAsync(path, record.ToJsonString());

        SavException ex = await Assert.ThrowsAsync<SavException>(
            () => store.GetAsync(created.Id, CancellationToken.None));
        Assert.Equal(SavErrorCode.AttestationIntegrityFailure, ex.Code);
    }

    [Fact]
    public async Task Get_normalizes_nested_collection_constructor_failure()
    {
        using TempStoreRoot root = TempStoreRoot.Create();
        FileAttestationStore store = CreateStore(root.Path);
        Attestation created = CreateSigned("att-nested-list");
        await store.SaveAsync(created, CancellationToken.None);

        string path = Path.Combine(root.Path, created.Id + ".json");
        JsonObject record = JsonNode.Parse(await File.ReadAllTextAsync(path))!.AsObject();
        record["analysis"]!["ir"]!["tablesRead"] = null;
        await File.WriteAllTextAsync(path, record.ToJsonString());

        SavException ex = await Assert.ThrowsAsync<SavException>(
            () => store.GetAsync(created.Id, CancellationToken.None));
        Assert.Equal(SavErrorCode.AttestationIntegrityFailure, ex.Code);
    }

    [Fact]
    public async Task Get_accepts_reordered_json_when_canonical_structure_and_hmac_are_unchanged()
    {
        using TempStoreRoot root = TempStoreRoot.Create();
        FileAttestationStore store = CreateStore(root.Path);
        Attestation created = CreateSigned("att-reordered-json");
        await store.SaveAsync(created, CancellationToken.None);

        string path = Path.Combine(root.Path, created.Id + ".json");
        JsonObject record = JsonNode.Parse(await File.ReadAllTextAsync(path))!.AsObject();
        JsonObject reordered = new();
        foreach (KeyValuePair<string, JsonNode?> property in record.Reverse())
        {
            reordered[property.Key] = property.Value?.DeepClone();
        }

        await File.WriteAllTextAsync(path, reordered.ToJsonString());
        Attestation? loaded = await store.GetAsync(created.Id, CancellationToken.None);
        Assert.NotNull(loaded);
        Assert.Equal(created.HmacSha256Base64, loaded.HmacSha256Base64);
    }

    [Fact]
    public async Task Save_rejects_attestation_with_bad_hmac()
    {
        using TempStoreRoot root = TempStoreRoot.Create();
        FileAttestationStore store = CreateStore(root.Path);
        Attestation created = CreateSigned("att-bad-hmac");
        Attestation forged = new(
            created.SchemaVersion,
            created.Id,
            created.SqlHash,
            created.ContractHash,
            created.PolicyHash,
            created.SavVersion,
            created.TargetAliasFingerprint,
            created.Decision,
            created.Analysis,
            created.PlanSummary,
            created.Properties,
            created.EffectiveDisclosure,
            created.Timestamp,
            hmacSha256Base64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");

        SavException ex = await Assert.ThrowsAsync<SavException>(
            () => store.SaveAsync(forged, CancellationToken.None));
        Assert.Equal(SavErrorCode.AttestationIntegrityFailure, ex.Code);
    }

    [Fact]
    public async Task Accepts_uuid_id()
    {
        using TempStoreRoot root = TempStoreRoot.Create();
        FileAttestationStore store = CreateStore(root.Path);
        string uuid = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
        Attestation created = CreateSigned(uuid);

        await store.SaveAsync(created, CancellationToken.None);
        Attestation? loaded = await store.GetAsync(uuid, CancellationToken.None);
        Assert.NotNull(loaded);
        Assert.Equal(uuid, loaded.Id);
    }

    private static FileAttestationStore CreateStore(string root) =>
        new(root, new AttestationHmac(), Key);

    private static Attestation CreateSigned(string id)
    {
        AttestationFactory factory = new(new AttestationHmac(), new PassThroughTestRedactor());
        StructuralSqlIr ir = new(
            dialect: "postgresql",
            statementTypes: ["SelectStmt"],
            tablesRead: [],
            tablesWritten: [],
            columnsRead: [],
            columnsWritten: [],
            functions: [],
            hasMultipleStatements: false,
            hasDynamicSql: false,
            unresolvedObjects: [],
            riskCodes: []);

        AttestationDraft draft = new(
            SchemaVersion: "1",
            Id: id,
            SqlHash: AttestationMacMaterial.ComputeSqlHash("SELECT 1"),
            ContractHash: "c",
            PolicyHash: "p",
            SavVersion: "0.0.0-test",
            TargetAliasFingerprint: "fp",
            Decision: AttestationDecision.Pass,
            Analysis: new AttestationAnalysis(ir, IsParsable: true),
            PlanSummary: null,
            Properties: [new PropertyResult("query_succeeds", PropertyStatus.Pass, null)],
            EffectiveDisclosure: DisclosureProfileMerge.StrictDefaults(),
            Timestamp: DateTimeOffset.Parse("2026-07-25T12:00:00Z"));

        return factory.Create(draft, Key);
    }

    private sealed class TempStoreRoot : IDisposable
    {
        private TempStoreRoot(string path) => Path = path;

        public string Path { get; }

        public static TempStoreRoot Create()
        {
            string path = System.IO.Path.Combine(
                System.IO.Path.GetTempPath(),
                "sav-attest-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(path);
            return new TempStoreRoot(path);
        }

        public void Dispose()
        {
            try
            {
                if (Directory.Exists(Path))
                {
                    Directory.Delete(Path, recursive: true);
                }
            }
            catch (IOException)
            {
                // best effort
            }
        }
    }
}
