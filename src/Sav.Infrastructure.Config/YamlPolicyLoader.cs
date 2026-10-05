using Sav.Application.Abstractions;
using Sav.Domain.Errors;
using Sav.Domain.Policies;
using Sav.Infrastructure.Config.Internal;
using YamlDotNet.Core;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace Sav.Infrastructure.Config;

public sealed class YamlPolicyLoader : IPolicyLoader
{
    private static readonly HashSet<string> AllowedCostBuckets = new(StringComparer.Ordinal)
    {
        "trivial",
        "low",
        "moderate",
        "high",
        "extreme",
    };

    private readonly IDeserializer _deserializer = new DeserializerBuilder()
        .WithNamingConvention(CamelCaseNamingConvention.Instance)
        .WithDuplicateKeyChecking()
        .Build();

    public Task<Policy> LoadAsync(string path, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        string yaml = YamlFileReader.ReadText(path, SavErrorCode.PolicyInvalid);
        PolicyYamlDocument document;
        try
        {
            document = _deserializer.Deserialize<PolicyYamlDocument>(yaml)
                ?? throw CreateInvalid("Policy document is empty.");
        }
        catch (YamlException)
        {
            throw CreateInvalid("Policy YAML could not be parsed.");
        }

        ValidateRequired(document);
        string maxCostBucket = document.MaxCostBucket!.Trim();
        if (!AllowedCostBuckets.Contains(maxCostBucket))
        {
            throw CreateInvalid("maxCostBucket is not in the closed vocabulary.");
        }

        DisclosureProfile disclosure = YamlDisclosureMapper.Map(
            document.Disclosure,
            SavErrorCode.PolicyInvalid);

        Policy policy = new(
            id: RequireText(document.Id, "id"),
            version: RequireText(document.Version, "version"),
            allowedStatementTypes: document.AllowedStatementTypes ?? [],
            deniedTables: TrimEntries(document.DeniedTables ?? []),
            deniedColumns: TrimEntries(document.DeniedColumns ?? []),
            allowedFunctions: document.AllowedFunctions ?? [],
            denyUnresolvedObjects: document.DenyUnresolvedObjects
                ?? throw CreateInvalid("denyUnresolvedObjects is required."),
            denyMultipleStatements: document.DenyMultipleStatements
                ?? throw CreateInvalid("denyMultipleStatements is required."),
            denyUpdateDeleteWithoutPredicate: document.DenyUpdateDeleteWithoutPredicate
                ?? throw CreateInvalid("denyUpdateDeleteWithoutPredicate is required."),
            maxCostBucket: maxCostBucket,
            forbiddenPlanNodes: TrimEntries(
                document.ForbiddenPlanNodes
                    ?? throw CreateInvalid("forbiddenPlanNodes is required.")),
            disclosure: disclosure);

        return Task.FromResult(policy);
    }

    private static void ValidateRequired(PolicyYamlDocument document)
    {
        if (string.IsNullOrWhiteSpace(document.MaxCostBucket))
        {
            throw CreateInvalid("maxCostBucket is required.");
        }

        if (document.AllowedStatementTypes is null)
        {
            throw CreateInvalid("allowedStatementTypes is required.");
        }

        if (document.DeniedTables is null)
        {
            throw CreateInvalid("deniedTables is required.");
        }

        if (document.DeniedColumns is null)
        {
            throw CreateInvalid("deniedColumns is required.");
        }

        if (document.AllowedFunctions is null)
        {
            throw CreateInvalid("allowedFunctions is required.");
        }

        if (document.ForbiddenPlanNodes is null)
        {
            throw CreateInvalid("forbiddenPlanNodes is required.");
        }

        if (document.Disclosure is null)
        {
            throw CreateInvalid("disclosure is required.");
        }
    }

    private static string[] TrimEntries(IEnumerable<string> values) =>
        values.Select(static value => value?.Trim() ?? string.Empty).ToArray();

    private static string RequireText(string? value, string field)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw CreateInvalid($"{field} is required.");
        }

        return value;
    }

    private static SavException CreateInvalid(string reason)
    {
        return new SavException(SavErrorCode.PolicyInvalid, $"policy_invalid: {reason}");
    }

    private sealed class PolicyYamlDocument
    {
        public string? Id { get; set; }

        public string? Version { get; set; }

        public List<string>? AllowedStatementTypes { get; set; }

        public List<string>? DeniedTables { get; set; }

        public List<string>? DeniedColumns { get; set; }

        public List<string>? AllowedFunctions { get; set; }

        public bool? DenyUnresolvedObjects { get; set; }

        public bool? DenyMultipleStatements { get; set; }

        public bool? DenyUpdateDeleteWithoutPredicate { get; set; }

        public string? MaxCostBucket { get; set; }

        public List<string>? ForbiddenPlanNodes { get; set; }

        public DisclosureYamlDocument? Disclosure { get; set; }
    }
}
