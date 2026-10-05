using Sav.Domain.Errors;
using Sav.Host.Composition;
using Sav.Host.Configuration;

namespace Sav.Host.Tests;

public sealed class SavModeOptionsResolveModeTests
{
    [Fact]
    public void Unknown_mode_does_not_resolve_to_Full()
    {
        SavException ex = Assert.Throws<SavException>(() => SavModeOptions.ResolveMode("AnalizeOnly"));
        Assert.Equal(SavErrorCode.ModeInvalid, ex.Code);
        Assert.Contains(SavErrorCode.ModeInvalid, ex.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("Full")]
    [InlineData("full")]
    [InlineData("AnalyzeOnly")]
    [InlineData("analyzeonly")]
    public void Known_modes_resolve(string value)
    {
        DiProfile mode = SavModeOptions.ResolveMode(value);
        Assert.True(mode is DiProfile.Full or DiProfile.AnalyzeOnly);
        if (value.Equals("Full", StringComparison.OrdinalIgnoreCase))
        {
            Assert.Equal(DiProfile.Full, mode);
        }
        else
        {
            Assert.Equal(DiProfile.AnalyzeOnly, mode);
        }
    }

    [Fact]
    public void Null_or_whitespace_defaults_to_Full()
    {
        Assert.Equal(DiProfile.Full, SavModeOptions.ResolveMode(null));
        Assert.Equal(DiProfile.Full, SavModeOptions.ResolveMode("  "));
    }
}
