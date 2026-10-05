using Sav.Domain.Errors;

namespace Sav.Domain.Tests;

public sealed class FixedPropertyDetailCodesTests
{
    [Theory]
    [InlineData(SavErrorCode.SchemaChanged)]
    [InlineData(SavErrorCode.SchemaInvariantFailed)]
    [InlineData(SavErrorCode.OrphansFound)]
    [InlineData(SavErrorCode.QueryFailed)]
    [InlineData(SavErrorCode.MvpAPropertiesRequired)]
    public void Contains_known_production_codes(string code)
    {
        Assert.True(FixedPropertyDetailCodes.Contains(code));
        Assert.Equal(code, FixedPropertyDetailCodes.Coerce(code));
    }

    [Theory]
    [InlineData("relation \"orders\" does not exist")]
    [InlineData("violates foreign key constraint \"fk\"")]
    [InlineData("syntax error at or near \"X\"")]
    [InlineData("")]
    [InlineData(null)]
    public void Coerce_free_text_to_query_failed(string? detail)
    {
        Assert.Equal(SavErrorCode.QueryFailed, FixedPropertyDetailCodes.Coerce(detail));
    }
}
