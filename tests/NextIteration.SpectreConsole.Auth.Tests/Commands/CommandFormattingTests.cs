using NextIteration.SpectreConsole.Auth.Commands;

using Xunit;

namespace NextIteration.SpectreConsole.Auth.Tests.Commands;

public sealed class CommandFormattingTests
{
    [Fact]
    public void ShortId_FullGuid_ReturnsFirstEightPlusEllipsis()
    {
        var id = "12345678-1234-1234-1234-123456789012";
        Assert.Equal("12345678...", CommandFormatting.ShortId(id));
    }

    [Theory]
    [InlineData("abc")]      // shorter than 8 — no slice attempted
    [InlineData("1234567")]  // exactly one short
    public void ShortId_ShortString_ReturnsFullStringWithoutThrowing(string id)
    {
        // Regression: previously every site sliced AccountId[..8] which
        // throws ArgumentOutOfRangeException for short user-supplied ids
        // (e.g. `accounts delete abc`).
        Assert.Equal(id, CommandFormatting.ShortId(id));
    }

    [Fact]
    public void ShortId_ExactlyEight_ReturnsValuePlusEllipsis()
    {
        Assert.Equal("12345678...", CommandFormatting.ShortId("12345678"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void ShortId_NullOrEmpty_ReturnsEmpty(string? id)
    {
        Assert.Equal(string.Empty, CommandFormatting.ShortId(id));
    }
}
