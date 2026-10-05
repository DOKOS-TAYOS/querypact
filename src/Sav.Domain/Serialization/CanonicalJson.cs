using System.Buffers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Sav.Domain.Serialization;

/// <summary>
/// Deterministic JSON for Domain hashing (ADR 0001 exception: System.Text.Json only).
/// No file I/O, YAML, or Npgsql.
/// </summary>
public static class CanonicalJson
{
    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DictionaryKeyPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = false,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.Never,
    };

    public static string Serialize<T>(T value)
    {
        return Encoding.UTF8.GetString(Utf8Bytes(value));
    }

    public static byte[] Utf8Bytes<T>(T value)
    {
        using JsonDocument document = JsonSerializer.SerializeToDocument(value, SerializerOptions);
        ArrayBufferWriter<byte> buffer = new();
        using (Utf8JsonWriter writer = new(buffer))
        {
            WriteCanonical(document.RootElement, writer);
        }

        return buffer.WrittenSpan.ToArray();
    }

    public static string Sha256Hex<T>(T value)
    {
        byte[] hash = SHA256.HashData(Utf8Bytes(value));
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private static void WriteCanonical(JsonElement element, Utf8JsonWriter writer)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                writer.WriteStartObject();
                foreach (JsonProperty property in element.EnumerateObject().OrderBy(
                    static property => property.Name,
                    StringComparer.Ordinal))
                {
                    writer.WritePropertyName(property.Name);
                    WriteCanonical(property.Value, writer);
                }

                writer.WriteEndObject();
                break;
            case JsonValueKind.Array:
                writer.WriteStartArray();
                foreach (JsonElement item in element.EnumerateArray())
                {
                    WriteCanonical(item, writer);
                }

                writer.WriteEndArray();
                break;
            case JsonValueKind.String:
                writer.WriteStringValue(element.GetString());
                break;
            case JsonValueKind.Number:
            case JsonValueKind.True:
            case JsonValueKind.False:
            case JsonValueKind.Null:
                element.WriteTo(writer);
                break;
            default:
                throw new InvalidOperationException($"Unsupported JSON token: {element.ValueKind}.");
        }
    }
}
