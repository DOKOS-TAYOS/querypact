using Sav.Application.Attestations;
using Sav.Domain.Attestations;
using Sav.Domain.Decisions;
using Sav.Domain.Policies;
using Sav.Domain.Properties;
using Sav.Infrastructure.Storage.Attestations;

namespace Sav.Infrastructure.Storage.Tests.Attestations;

public sealed class FileAttestationStoreConcurrencyTests
{
    private static readonly byte[] Key = Enumerable.Repeat((byte)0x66, 32).ToArray();

    [Fact]
    public async Task Parallel_save_and_get_do_not_tear_or_cross_ids()
    {
        string root = Path.Combine(Path.GetTempPath(), "sav-attest-conc-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            FileAttestationStore store = new(root, new AttestationHmac(), Key);
            const int count = 32;
            Attestation[] items = Enumerable.Range(0, count)
                .Select(i => CreateSigned($"id-{i:D4}"))
                .ToArray();

            await Task.WhenAll(items.Select(a => store.SaveAsync(a, CancellationToken.None)));

            Attestation?[] loaded = await Task.WhenAll(
                items.Select(a => store.GetAsync(a.Id, CancellationToken.None)));

            for (int i = 0; i < count; i++)
            {
                Assert.NotNull(loaded[i]);
                Assert.Equal(items[i].Id, loaded[i]!.Id);
                Assert.Equal(items[i].HmacSha256Base64, loaded[i]!.HmacSha256Base64);
                Assert.Equal(items[i].SqlHash, loaded[i]!.SqlHash);
            }

            // Parallel overwrite of the same id must leave a valid readable attestation.
            Attestation v1 = CreateSigned("shared-id", sql: "SELECT 1");
            Attestation v2 = CreateSigned("shared-id", sql: "SELECT 2");
            await Task.WhenAll(
                store.SaveAsync(v1, CancellationToken.None),
                store.SaveAsync(v2, CancellationToken.None));

            Attestation? final = await store.GetAsync("shared-id", CancellationToken.None);
            Assert.NotNull(final);
            Assert.True(
                final.SqlHash == v1.SqlHash || final.SqlHash == v2.SqlHash,
                "Final attestation must be one complete version, not a torn mix.");
            Assert.True(AttestationFactory.VerifyIntegrity(final, new AttestationHmac(), Key));
            Assert.Empty(Directory.GetFiles(root, "*.tmp"));
        }
        finally
        {
            try
            {
                Directory.Delete(root, recursive: true);
            }
            catch (IOException)
            {
                // best effort
            }
        }
    }
    [Fact]
    public async Task Parallel_same_id_saves_and_gets_return_complete_valid_versions()
    {
        string root = Path.Combine(Path.GetTempPath(), "sav-attest-mixed-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            FileAttestationStore store = new(root, new AttestationHmac(), Key);
            Attestation v1 = CreateSigned("shared-mixed-id", sql: "SELECT 1");
            Attestation v2 = CreateSigned("shared-mixed-id", sql: "SELECT 2");
            await store.SaveAsync(v1, CancellationToken.None);

            Task[] saves = Enumerable.Range(0, 24)
                .Select(index => store.SaveAsync(index % 2 == 0 ? v1 : v2, CancellationToken.None))
                .ToArray();
            Task<Attestation?>[] reads = Enumerable.Range(0, 24)
                .Select(_ => store.GetAsync(v1.Id, CancellationToken.None))
                .ToArray();

            await Task.WhenAll(saves.Concat(reads));

            foreach (Task<Attestation?> read in reads)
            {
                Attestation loaded = Assert.IsType<Attestation>(await read);
                Assert.True(loaded.SqlHash == v1.SqlHash || loaded.SqlHash == v2.SqlHash);
                Assert.True(AttestationFactory.VerifyIntegrity(loaded, new AttestationHmac(), Key));
            }

            Assert.Empty(Directory.GetFiles(root, "*.tmp"));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task Get_missing_waits_for_path_gate_before_checking_existence()
    {
        string root = Path.Combine(Path.GetTempPath(), "sav-attest-probe-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            FileAttestationStore store = new(root, new AttestationHmac(), Key);
            const string id = "missing-probe-id";
            SemaphoreSlim gate = store.GetIoGateForTesting(id);
            await gate.WaitAsync();
            Task<Attestation?> pending;
            try
            {
                pending = store.GetAsync(id, CancellationToken.None);
                Assert.False(pending.IsCompleted);
            }
            finally
            {
                gate.Release();
            }

            Assert.Null(await pending);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Cancellation_while_waiting_for_path_gate_does_not_block_later_operation(bool fileExists)
    {
        string root = Path.Combine(Path.GetTempPath(), "sav-attest-cancel-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            FileAttestationStore store = new(root, new AttestationHmac(), Key);
            Attestation created = CreateSigned("cancel-wait-id");
            if (fileExists)
            {
                await store.SaveAsync(created, CancellationToken.None);
            }

            SemaphoreSlim gate = store.GetIoGateForTesting(created.Id);
            await gate.WaitAsync();
            try
            {
                using CancellationTokenSource cancellation = new();
                Task<Attestation?> pending = store.GetAsync(created.Id, cancellation.Token);
                Assert.False(pending.IsCompleted);
                cancellation.Cancel();
                await Assert.ThrowsAnyAsync<OperationCanceledException>(() => pending);
            }
            finally
            {
                gate.Release();
            }

            if (!fileExists)
            {
                Assert.Null(await store.GetAsync(created.Id, CancellationToken.None));
                await store.SaveAsync(created, CancellationToken.None);
            }

            Attestation? loaded = await store.GetAsync(created.Id, CancellationToken.None);
            Assert.NotNull(loaded);
            Assert.Equal(created.HmacSha256Base64, loaded.HmacSha256Base64);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static Attestation CreateSigned(string id, string sql = "SELECT 1")
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
                SqlHash: AttestationMacMaterial.ComputeSqlHash(sql),
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
}
