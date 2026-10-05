using System.Text;
using System.Text.Json;
using Sav.Application.Abstractions;
using Sav.Application.Attestations;
using Sav.Domain.Attestations;
using Sav.Domain.Decisions;
using Sav.Domain.Errors;
using Sav.Domain.Plans;
using Sav.Domain.Policies;
using Sav.Domain.Properties;
using Sav.Domain.Serialization;

namespace Sav.Infrastructure.Storage.Attestations;

/// <summary>
/// File-backed <see cref="IAttestationStore"/>. Paths are always
/// <c>{StoreRoot}/{validatedId}.json</c> after <see cref="AttestationIdGuard"/>.
/// Integrity via injected <see cref="IAttestationMac"/> (no local HMAC duplicate).
/// </summary>
public sealed class FileAttestationStore : IAttestationStore
{
    private const int IoGateCount = 64;

    private static readonly JsonSerializerOptions DeserializeOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    private readonly string _storeRootFull;
    private readonly IAttestationMac _mac;
    private readonly byte[] _hmacKey;
    private readonly SemaphoreSlim[] _ioGates = CreateIoGates();

    public FileAttestationStore(string storeRoot, IAttestationMac mac, byte[] hmacKey)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(storeRoot);
        ArgumentNullException.ThrowIfNull(mac);
        ArgumentNullException.ThrowIfNull(hmacKey);
        if (hmacKey.Length < 32)
        {
            throw new ArgumentException("HMAC key must be at least 32 bytes.", nameof(hmacKey));
        }

        if (!Path.IsPathRooted(storeRoot))
        {
            throw new ArgumentException(
                "Sav:AttestationStoreRoot must be an absolute directory.",
                nameof(storeRoot));
        }

        _storeRootFull = NormalizeDirectory(Path.GetFullPath(storeRoot));
        Directory.CreateDirectory(_storeRootFull);
        _mac = mac;
        _hmacKey = hmacKey.ToArray();
    }

    public string StoreRoot => _storeRootFull;

    public async Task<string> SaveAsync(Attestation attestation, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(attestation);
        cancellationToken.ThrowIfCancellationRequested();

        AttestationIdGuard.EnsureValid(attestation.Id);
        if (!AttestationFactory.VerifyIntegrity(attestation, _mac, _hmacKey))
        {
            throw new SavException(
                SavErrorCode.AttestationIntegrityFailure,
                $"{SavErrorCode.AttestationIntegrityFailure}: Refusing to persist attestation with invalid HMAC.");
        }

        string path = ResolvePathUnderStore(attestation.Id);
        string json = CanonicalJson.Serialize(AttestationPersistenceModel.FromDomain(attestation));
        string tempPath = path + ".tmp";

        SemaphoreSlim ioGate = GetIoGate(path);
        await ioGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await File.WriteAllTextAsync(tempPath, json, Encoding.UTF8, cancellationToken)
                .ConfigureAwait(false);
            File.Move(tempPath, path, overwrite: true);
        }
        finally
        {
            // Cleanup must remain within the gate: another save of the same id
            // may otherwise recreate tempPath before this save deletes it.
            TryDelete(tempPath);
            ioGate.Release();
        }

        return attestation.Id;
    }

    public async Task<Attestation?> GetAsync(string attestationId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        AttestationIdGuard.EnsureValid(attestationId);

        string path = ResolvePathUnderStore(attestationId);
        string json;
        SemaphoreSlim ioGate = GetIoGate(path);
        await ioGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            // On Windows, even an existence probe can interfere with an overwrite
            // rename. Keep all filesystem access for this path within the gate.
            if (!File.Exists(path))
            {
                return null;
            }

            json = await File.ReadAllTextAsync(path, Encoding.UTF8, cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            ioGate.Release();
        }

        AttestationPersistenceModel? model;
        string storedCanonical;
        try
        {
            using JsonDocument stored = JsonDocument.Parse(json);
            storedCanonical = CanonicalJson.Serialize(stored.RootElement);
            model = JsonSerializer.Deserialize<AttestationPersistenceModel>(stored.RootElement, DeserializeOptions);
        }
        catch (Exception ex) when (ex is JsonException or ArgumentException)
        {
            // Nested record constructors can reject null collections during
            // deserialization. Normalize those malformed-payload failures too.
            throw new SavException(
                SavErrorCode.AttestationIntegrityFailure,
                $"{SavErrorCode.AttestationIntegrityFailure}: Attestation file is structurally invalid.");
        }

        if (model is null)
        {
            throw new SavException(
                SavErrorCode.AttestationIntegrityFailure,
                $"{SavErrorCode.AttestationIntegrityFailure}: Attestation file is empty.");
        }

        if (!model.HasRequiredFields())
        {
            throw new SavException(
                SavErrorCode.AttestationIntegrityFailure,
                $"{SavErrorCode.AttestationIntegrityFailure}: Attestation file is missing required fields.");
        }

        Attestation attestation = model.ToDomain();
        // A missing boolean or timestamp may deserialize to its CLR default, so
        // checking only references and then the HMAC is insufficient: the same
        // canonical MAC input can be reconstructed from an incomplete file.
        // Compare canonical JSON structures before integrity verification. This
        // preserves harmless property reordering but rejects omitted/extra keys.
        if (!string.Equals(
                storedCanonical,
                CanonicalJson.Serialize(AttestationPersistenceModel.FromDomain(attestation)),
                StringComparison.Ordinal))
        {
            throw new SavException(
                SavErrorCode.AttestationIntegrityFailure,
                $"{SavErrorCode.AttestationIntegrityFailure}: Attestation structure does not match its stored model.");
        }

        if (!string.Equals(attestation.Id, attestationId, StringComparison.Ordinal))
        {
            throw new SavException(
                SavErrorCode.AttestationIntegrityFailure,
                $"{SavErrorCode.AttestationIntegrityFailure}: Stored id does not match requested id.");
        }

        if (!AttestationFactory.VerifyIntegrity(attestation, _mac, _hmacKey))
        {
            throw new SavException(
                SavErrorCode.AttestationIntegrityFailure,
                $"{SavErrorCode.AttestationIntegrityFailure}: Attestation HMAC verification failed.");
        }

        return attestation;
    }

    private string ResolvePathUnderStore(string validatedId)
    {
        // Id already allow-listed: never concatenate raw agent input before EnsureValid.
        string combined = Path.Combine(_storeRootFull, validatedId + ".json");
        string full = Path.GetFullPath(combined);
        if (!IsUnderStoreRoot(full))
        {
            throw new SavException(
                SavErrorCode.AttestationIdInvalid,
                $"{SavErrorCode.AttestationIdInvalid}: Resolved path escapes store root.");
        }

        return full;
    }

    private SemaphoreSlim GetIoGate(string fullPath)
    {
        int hash = StringComparer.OrdinalIgnoreCase.GetHashCode(fullPath);
        return _ioGates[hash & (IoGateCount - 1)];
    }

    internal SemaphoreSlim GetIoGateForTesting(string validatedId)
    {
        AttestationIdGuard.EnsureValid(validatedId);
        return GetIoGate(ResolvePathUnderStore(validatedId));
    }

    private static SemaphoreSlim[] CreateIoGates() =>
        Enumerable.Range(0, IoGateCount)
            .Select(_ => new SemaphoreSlim(1, 1))
            .ToArray();

    private bool IsUnderStoreRoot(string fullFilePath)
    {
        string directory = NormalizeDirectory(Path.GetDirectoryName(fullFilePath) ?? fullFilePath);
        if (string.Equals(directory, _storeRootFull, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        string rootPrefix = _storeRootFull + Path.DirectorySeparatorChar;
        return fullFilePath.StartsWith(rootPrefix, StringComparison.OrdinalIgnoreCase);
    }

    private static string NormalizeDirectory(string path) =>
        Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);

    private static void TryDelete(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch (IOException)
        {
            // Best-effort cleanup of temp file.
        }
        catch (UnauthorizedAccessException)
        {
            // Best-effort cleanup of temp file.
        }
    }

    private sealed record AttestationPersistenceModel(
        string SchemaVersion,
        string Id,
        string SqlHash,
        string ContractHash,
        string PolicyHash,
        string SavVersion,
        string TargetAliasFingerprint,
        string Decision,
        AttestationAnalysis Analysis,
        PlanSummary? PlanSummary,
        PropertyResult[] Properties,
        DisclosureProfile EffectiveDisclosure,
        DateTimeOffset Timestamp,
        string HmacSha256Base64)
    {
        // System.Text.Json accepts missing or explicit null values in constructor
        // parameters even when the C# types are non-nullable. Reject the resulting
        // invalid object before domain construction or HMAC comparison can throw
        // untyped exceptions or accept an incomplete structural payload.
        public bool HasRequiredFields() =>
            SchemaVersion is not null &&
            Id is not null &&
            SqlHash is not null &&
            ContractHash is not null &&
            PolicyHash is not null &&
            SavVersion is not null &&
            TargetAliasFingerprint is not null &&
            Decision is not null &&
            Analysis is { Ir: not null } &&
            Properties is not null &&
            Properties.All(static property => property is not null) &&
            EffectiveDisclosure is { Name: not null } &&
            HmacSha256Base64 is not null;

        public static AttestationPersistenceModel FromDomain(Attestation attestation) =>
            new(
                SchemaVersion: attestation.SchemaVersion,
                Id: attestation.Id,
                SqlHash: attestation.SqlHash,
                ContractHash: attestation.ContractHash,
                PolicyHash: attestation.PolicyHash,
                SavVersion: attestation.SavVersion,
                TargetAliasFingerprint: attestation.TargetAliasFingerprint,
                Decision: AttestationDecisionMapper.ToWire(attestation.Decision),
                Analysis: attestation.Analysis,
                PlanSummary: attestation.PlanSummary,
                Properties: attestation.Properties.ToArray(),
                EffectiveDisclosure: attestation.EffectiveDisclosure,
                Timestamp: attestation.Timestamp,
                HmacSha256Base64: attestation.HmacSha256Base64);

        public Attestation ToDomain()
        {
            AttestationDecision decision = ParseDecision(Decision);
            return new Attestation(
                schemaVersion: SchemaVersion,
                id: Id,
                sqlHash: SqlHash,
                contractHash: ContractHash,
                policyHash: PolicyHash,
                savVersion: SavVersion,
                targetAliasFingerprint: TargetAliasFingerprint,
                decision: decision,
                analysis: Analysis,
                planSummary: PlanSummary,
                properties: Properties,
                effectiveDisclosure: EffectiveDisclosure,
                timestamp: Timestamp,
                hmacSha256Base64: HmacSha256Base64);
        }

        private static AttestationDecision ParseDecision(string wire) =>
            wire switch
            {
                "PASS" => AttestationDecision.Pass,
                "FAIL" => AttestationDecision.Fail,
                "REVIEW" => AttestationDecision.Review,
                "DENY" => AttestationDecision.Deny,
                _ => throw new SavException(
                    SavErrorCode.AttestationIntegrityFailure,
                    $"{SavErrorCode.AttestationIntegrityFailure}: Unknown decision wire value."),
            };
    }
}
