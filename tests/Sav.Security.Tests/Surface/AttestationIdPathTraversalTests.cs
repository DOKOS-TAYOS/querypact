using Sav.Application.Attestations;
using Sav.Domain.Attestations;
using Sav.Domain.Decisions;
using Sav.Domain.Errors;
using Sav.Domain.Policies;
using Sav.Domain.Properties;
using Sav.Infrastructure.Storage.Attestations;
using Sav.Security.Tests.Helpers;

namespace Sav.Security.Tests.Surface;

public sealed class AttestationIdPathTraversalTests
{
    private static readonly byte[] Key = Enumerable.Repeat((byte)0x77, 32).ToArray();

    public static TheoryData<string> TraversalIds { get; } = new()
    {
        "../etc/passwd",
        "..\\windows\\system.ini",
        "/etc/passwd",
        "C:\\Windows\\system.ini",
        "nested/../escape",
        "foo/bar",
        "foo\\bar",
        "..",
        "...",
        "a.b",
        "att.json",
        "%2e%2e%2fpasswd",
        "id/with/slash",
        "id\0null",
        "",
        "   ",
        new string('x', 65),
    };

    [Theory]
    [MemberData(nameof(TraversalIds))]
    public void Guard_rejects_traversal_and_invalid_ids(string id)
    {
        SavException ex = Assert.Throws<SavException>(() => AttestationIdGuard.EnsureValid(id));
        Assert.Equal(SavErrorCode.AttestationIdInvalid, ex.Code);
    }

    [Theory]
    [InlineData("ok-id_01")]
    [InlineData("a1b2c3d4-e5f6-7890-abcd-ef1234567890")]
    [InlineData("A1B2C3D4-E5F6-7890-ABCD-EF1234567890")]
    public void Guard_accepts_allow_listed_ids(string id)
    {
        AttestationIdGuard.EnsureValid(id);
        Assert.True(AttestationIdGuard.IsValid(id));
    }

    [Theory]
    [MemberData(nameof(TraversalIds))]
    public async Task Store_get_rejects_traversal_with_zero_files_outside_root(string id)
    {
        using TempRoots roots = TempRoots.Create();
        FileAttestationStore store = new(roots.StoreRoot, new AttestationHmac(), Key);
        string outsideMarker = Path.Combine(roots.OutsideRoot, "must-not-appear.json");
        Assert.False(File.Exists(outsideMarker));

        int outsideBefore = Directory.GetFiles(roots.OutsideRoot, "*", SearchOption.AllDirectories).Length;
        int storeBefore = Directory.GetFiles(roots.StoreRoot, "*", SearchOption.AllDirectories).Length;

        SavException ex = await Assert.ThrowsAsync<SavException>(
            () => store.GetAsync(id, CancellationToken.None));

        Assert.Equal(SavErrorCode.AttestationIdInvalid, ex.Code);
        Assert.Equal(
            outsideBefore,
            Directory.GetFiles(roots.OutsideRoot, "*", SearchOption.AllDirectories).Length);
        Assert.Equal(
            storeBefore,
            Directory.GetFiles(roots.StoreRoot, "*", SearchOption.AllDirectories).Length);
        Assert.False(File.Exists(outsideMarker));
        Assert.DoesNotContain(roots.OutsideSecret, ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Store_get_succeeds_only_for_allow_listed_id_under_store_root()
    {
        using TempRoots roots = TempRoots.Create();
        FileAttestationStore store = new(roots.StoreRoot, new AttestationHmac(), Key);
        Attestation created = CreateSigned("safe-id-1");
        await store.SaveAsync(created, CancellationToken.None);

        Assert.True(File.Exists(Path.Combine(roots.StoreRoot, "safe-id-1.json")));
        Assert.False(File.Exists(Path.Combine(roots.OutsideRoot, "safe-id-1.json")));

        Attestation? loaded = await store.GetAsync("safe-id-1", CancellationToken.None);
        Assert.NotNull(loaded);
        Assert.Equal("safe-id-1", loaded.Id);
    }

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

        return factory.Create(
            new AttestationDraft(
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
                Timestamp: DateTimeOffset.Parse("2026-07-25T12:00:00Z")),
            Key);
    }

    private sealed class TempRoots : IDisposable
    {
        private TempRoots(string basePath, string storeRoot, string outsideRoot, string outsideSecret)
        {
            BasePath = basePath;
            StoreRoot = storeRoot;
            OutsideRoot = outsideRoot;
            OutsideSecret = outsideSecret;
        }

        public string BasePath { get; }

        public string StoreRoot { get; }

        public string OutsideRoot { get; }

        public string OutsideSecret { get; }

        public static TempRoots Create()
        {
            string basePath = Path.Combine(Path.GetTempPath(), "sav-idguard-" + Guid.NewGuid().ToString("N"));
            string storeRoot = Path.Combine(basePath, "store");
            string outsideRoot = Path.Combine(basePath, "outside");
            Directory.CreateDirectory(storeRoot);
            Directory.CreateDirectory(outsideRoot);
            string secretPath = Path.Combine(outsideRoot, "secret.txt");
            const string secret = "OUTSIDE_SECRET_MUST_NOT_LEAK";
            File.WriteAllText(secretPath, secret);
            return new TempRoots(basePath, storeRoot, outsideRoot, secret);
        }

        public void Dispose()
        {
            try
            {
                if (Directory.Exists(BasePath))
                {
                    Directory.Delete(BasePath, recursive: true);
                }
            }
            catch (IOException)
            {
                // best effort
            }
        }
    }
}
