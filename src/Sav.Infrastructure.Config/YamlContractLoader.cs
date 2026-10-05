using Sav.Application.Abstractions;
using Sav.Domain.Contracts;
using Sav.Domain.Errors;
using Sav.Domain.Policies;
using Sav.Infrastructure.Config.Internal;
using YamlDotNet.Core;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace Sav.Infrastructure.Config;

public sealed class YamlContractLoader : IContractLoader
{
    private readonly IDeserializer _deserializer = new DeserializerBuilder()
        .WithNamingConvention(CamelCaseNamingConvention.Instance)
        .WithDuplicateKeyChecking()
        .Build();

    public Task<Contract> LoadAsync(string path, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        string yaml = YamlFileReader.ReadText(path, SavErrorCode.ContractInvalid);
        ContractYamlDocument document;
        try
        {
            document = _deserializer.Deserialize<ContractYamlDocument>(yaml)
                ?? throw CreateInvalid("Contract document is empty.");
        }
        catch (YamlException)
        {
            throw CreateInvalid("Contract YAML could not be parsed.");
        }

        if (string.IsNullOrWhiteSpace(document.Id) || string.IsNullOrWhiteSpace(document.Version))
        {
            throw CreateInvalid("id and version are required.");
        }

        if (document.RequiredProperties is null)
        {
            throw CreateInvalid("requiredProperties is required.");
        }

        if (document.RequiredProperties.Count == 0)
        {
            throw CreateInvalid("requiredProperties must not be empty.");
        }

        if (document.Disclosure is null)
        {
            throw CreateInvalid("disclosure is required.");
        }

        List<PropertySpec> specs = [];
        foreach (PropertySpecYamlNode node in document.RequiredProperties)
        {
            specs.Add(MapPropertySpec(node));
        }

        DisclosureProfile disclosure = YamlDisclosureMapper.Map(
            document.Disclosure,
            SavErrorCode.ContractInvalid);

        Contract contract = new(
            id: document.Id,
            version: document.Version,
            requiredProperties: specs,
            disclosure: disclosure);

        return Task.FromResult(contract);
    }

    private static PropertySpec MapPropertySpec(PropertySpecYamlNode node)
    {
        if (node.IsStringOnly)
        {
            throw CreateInvalid("requiredProperties must be objects with a name field, not bare strings.");
        }

        if (string.IsNullOrWhiteSpace(node.Name))
        {
            throw CreateInvalid("requiredProperties entry is missing name.");
        }

        return node.Name.Trim() switch
        {
            "query_succeeds" => new QuerySucceedsSpec(),
            "empty_result" => new EmptyResultSpec(),
            "unique" => MapColumnSpec(node, static c => new UniqueSpec(c)),
            "non_null" => MapColumnSpec(node, static c => new NonNullSpec(c)),
            "query_equivalent" => new QueryEquivalentSpec(),
            "affected_rows" => MapAffectedRowsSpec(node),
            "schema_invariant" => MapSchemaInvariantSpec(node),
            "no_new_orphans" => MapNoNewOrphansSpec(node),
            _ => throw CreateInvalid($"Unknown property name '{node.Name}'."),
        };
    }

    private static PropertySpec MapColumnSpec(
        PropertySpecYamlNode node,
        Func<string, PropertySpec> factory)
    {
        if (string.IsNullOrWhiteSpace(node.Column))
        {
            throw CreateInvalid($"property '{node.Name}' requires a column field.");
        }

        return factory(node.Column.Trim());
    }

    private static PropertySpec MapAffectedRowsSpec(PropertySpecYamlNode node)
    {
        if (node.MinInclusive is null)
        {
            throw CreateInvalid("property 'affected_rows' requires minInclusive.");
        }

        if (node.MaxInclusive is long max && max < node.MinInclusive.Value)
        {
            throw CreateInvalid("property 'affected_rows' requires maxInclusive >= minInclusive.");
        }

        return new AffectedRowsSpec(node.MinInclusive.Value, node.MaxInclusive);
    }

    private static PropertySpec MapSchemaInvariantSpec(PropertySpecYamlNode node)
    {
        if (node.Requirements is null || node.Requirements.Count == 0)
        {
            throw CreateInvalid("property 'schema_invariant' requires requirements.");
        }

        return new SchemaInvariantSpec(node.Requirements);
    }

    private static PropertySpec MapNoNewOrphansSpec(PropertySpecYamlNode node)
    {
        if (string.IsNullOrWhiteSpace(node.ParentTable)
            || string.IsNullOrWhiteSpace(node.ParentKey)
            || string.IsNullOrWhiteSpace(node.ChildTable)
            || string.IsNullOrWhiteSpace(node.ChildKey))
        {
            throw CreateInvalid(
                "property 'no_new_orphans' requires parentTable, parentKey, childTable, childKey.");
        }

        return new NoNewOrphansSpec(
            node.ParentTable.Trim(),
            node.ParentKey.Trim(),
            node.ChildTable.Trim(),
            node.ChildKey.Trim());
    }

    private static SavException CreateInvalid(string reason)
    {
        return new SavException(SavErrorCode.ContractInvalid, $"contract_invalid: {reason}");
    }

    private sealed class ContractYamlDocument
    {
        public string? Id { get; set; }

        public string? Version { get; set; }

        public List<PropertySpecYamlNode>? RequiredProperties { get; set; }

        public DisclosureYamlDocument? Disclosure { get; set; }
    }

    /// <summary>
    /// YamlDotNet node that rejects bare string property entries (fail closed).
    /// </summary>
    private sealed class PropertySpecYamlNode : IYamlConvertible
    {
        public string? Name { get; private set; }

        public string? Column { get; private set; }

        public long? MinInclusive { get; private set; }

        public long? MaxInclusive { get; private set; }

        public string? ParentTable { get; private set; }

        public string? ParentKey { get; private set; }

        public string? ChildTable { get; private set; }

        public string? ChildKey { get; private set; }

        public List<SchemaInvariantRequirement>? Requirements { get; private set; }

        public bool IsStringOnly { get; private set; }

        public void Read(IParser parser, Type expectedType, ObjectDeserializer nestedObjectDeserializer)
        {
            if (parser.Accept<YamlDotNet.Core.Events.Scalar>(out YamlDotNet.Core.Events.Scalar? scalar)
                && scalar is not null
                && scalar.Value is not null)
            {
                IsStringOnly = true;
                Name = scalar.Value;
                parser.MoveNext();
                return;
            }

            object? raw = nestedObjectDeserializer(typeof(Dictionary<string, object?>));
            if (raw is Dictionary<object, object?> map)
            {
                ApplyMap(NormalizeMap(map, "requiredProperties entry"));
                return;
            }

            if (raw is Dictionary<string, object?> stringMap)
            {
                ApplyMap(stringMap);
                return;
            }

            throw CreateInvalid("requiredProperties entry must be an object.");
        }

        private void ApplyMap(IReadOnlyDictionary<string, object?> map)
        {
            Name = Get(map, "name")?.ToString();
            ValidatePropertyFields(map.Keys, Name);
            Column = Get(map, "column")?.ToString();
            MinInclusive = ParseOptionalLong(Get(map, "minInclusive"));
            MaxInclusive = ParseOptionalLong(Get(map, "maxInclusive"));
            ParentTable = Get(map, "parentTable")?.ToString();
            ParentKey = Get(map, "parentKey")?.ToString();
            ChildTable = Get(map, "childTable")?.ToString();
            ChildKey = Get(map, "childKey")?.ToString();
            Requirements = ParseRequirements(Get(map, "requirements"));
        }

        private static object? Get(IReadOnlyDictionary<string, object?> map, string key) =>
            map.TryGetValue(key, out object? value) ? value : null;

        private static void ValidatePropertyFields(IEnumerable<string> keys, string? name)
        {
            if (string.IsNullOrWhiteSpace(name))
            {
                return;
            }

            string[] allowed = name.Trim() switch
            {
                "query_succeeds" or "empty_result" or "query_equivalent" =>
                    ["name"],
                "unique" or "non_null" =>
                    ["name", "column"],
                "affected_rows" =>
                    ["name", "minInclusive", "maxInclusive"],
                "schema_invariant" =>
                    ["name", "requirements"],
                "no_new_orphans" =>
                    ["name", "parentTable", "parentKey", "childTable", "childKey"],
                _ => [],
            };

            if (allowed.Length == 0)
            {
                return;
            }

            HashSet<string> allowedSet = new(allowed, StringComparer.Ordinal);
            foreach (string key in keys)
            {
                if (!allowedSet.Contains(key))
                {
                    throw CreateInvalid($"property '{name.Trim()}' contains unknown field '{key}'.");
                }
            }
        }

        private static Dictionary<string, object?> NormalizeMap(
            Dictionary<object, object?> map,
            string context)
        {
            Dictionary<string, object?> normalized = new(StringComparer.Ordinal);
            foreach (KeyValuePair<object, object?> pair in map)
            {
                if (pair.Key is not string key)
                {
                    throw CreateInvalid($"{context} fields must use string keys.");
                }

                normalized[key] = pair.Value;
            }

            return normalized;
        }

        private static List<SchemaInvariantRequirement>? ParseRequirements(object? value)
        {
            if (value is null)
            {
                return null;
            }

            if (value is not System.Collections.IEnumerable enumerable || value is string)
            {
                throw CreateInvalid("schema_invariant requirements must be a list.");
            }

            List<SchemaInvariantRequirement> list = [];
            foreach (object? item in enumerable)
            {
                list.Add(ParseRequirement(item));
            }

            return list;
        }

        private static SchemaInvariantRequirement ParseRequirement(object? item)
        {
            IReadOnlyDictionary<string, object?> map = item switch
            {
                Dictionary<object, object?> objectMap =>
                    NormalizeMap(objectMap, "schema_invariant requirement"),
                Dictionary<string, object?> stringMap => stringMap,
                _ => throw CreateInvalid("schema_invariant requirement must be an object."),
            };

            HashSet<string> allowed = new(["relationName", "relkind"], StringComparer.Ordinal);
            foreach (string key in map.Keys)
            {
                if (!allowed.Contains(key))
                {
                    throw CreateInvalid(
                        $"schema_invariant requirement contains unknown field '{key}'.");
                }
            }

            string? relationName = Get(map, "relationName")?.ToString();
            string? relkind = Get(map, "relkind")?.ToString();
            if (string.IsNullOrWhiteSpace(relationName) || string.IsNullOrWhiteSpace(relkind))
            {
                throw CreateInvalid("schema_invariant requirement requires relationName and relkind.");
            }

            string normalizedRelkind = relkind.Trim();
            if (!SchemaInvariantRelkindVocabulary.IsSupported(normalizedRelkind))
            {
                throw CreateInvalid("schema_invariant requirement relkind is unsupported.");
            }

            return new SchemaInvariantRequirement(relationName.Trim(), normalizedRelkind);
        }

        private static long? ParseOptionalLong(object? value)
        {
            if (value is null)
            {
                return null;
            }

            if (value is long l)
            {
                return l;
            }

            if (value is int i)
            {
                return i;
            }

            if (long.TryParse(value.ToString(), out long parsed))
            {
                return parsed;
            }

            throw CreateInvalid("minInclusive/maxInclusive must be integers.");
        }

        public void Write(IEmitter emitter, ObjectSerializer nestedObjectSerializer)
        {
            throw new NotSupportedException();
        }
    }
}
