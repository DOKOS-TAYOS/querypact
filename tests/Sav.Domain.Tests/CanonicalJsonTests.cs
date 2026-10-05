using Sav.Domain.Serialization;

namespace Sav.Domain.Tests;

public sealed class CanonicalJsonTests
{
    private sealed record SampleDto(string Zulu, string Alpha, int Count);

    [Fact]
    public void Serialize_orders_object_properties_by_ordinal_key()
    {
        SampleDto value = new(Zulu: "z", Alpha: "a", Count: 2);

        string json = CanonicalJson.Serialize(value);

        Assert.Equal("""{"alpha":"a","count":2,"zulu":"z"}""", json);
    }

    [Fact]
    public void Serialize_orders_dictionary_keys_stably()
    {
        Dictionary<string, int> unsorted = new()
        {
            ["m"] = 1,
            ["a"] = 2,
            ["z"] = 3,
        };

        string json = CanonicalJson.Serialize(unsorted);

        Assert.Equal("""{"a":2,"m":1,"z":3}""", json);
    }

    [Fact]
    public void Serialize_preserves_nested_canonical_json_and_null_members()
    {
        var value = new
        {
            Z = new object?[] { null, new Dictionary<string, string> { ["zKey"] = "é", ["aKey"] = "quote \" and newline\n" } },
            A = new[] { 2, 1 },
        };

        string json = CanonicalJson.Serialize(value);

        Assert.Equal("""{"a":[2,1],"z":[null,{"aKey":"quote \u0022 and newline\n","zKey":"\u00E9"}]}""", json);
    }

    [Fact]
    public void Utf8Bytes_are_the_exact_utf8_encoding_of_Serialize()
    {
        var value = new { Z = "漢字😀", A = true };

        Assert.Equal(System.Text.Encoding.UTF8.GetBytes(CanonicalJson.Serialize(value)), CanonicalJson.Utf8Bytes(value));
    }

    [Fact]
    public void Sha256Hex_is_identical_across_runs()
    {
        SampleDto value = new(Zulu: "z", Alpha: "a", Count: 2);

        string first = CanonicalJson.Sha256Hex(value);
        string second = CanonicalJson.Sha256Hex(value);

        Assert.Equal(first, second);
        Assert.Equal(64, first.Length);
    }

    [Fact]
    public void Sha256Hex_changes_when_payload_changes()
    {
        string left = CanonicalJson.Sha256Hex(new SampleDto("z", "a", 1));
        string right = CanonicalJson.Sha256Hex(new SampleDto("z", "a", 2));

        Assert.NotEqual(left, right);
    }
}
