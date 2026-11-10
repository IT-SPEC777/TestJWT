using OAuthM2M.Client.Security;

namespace OAuthM2M.Client.Tests;

public sealed class SecretMaskerTests
{
    [Theory]
    [InlineData(null, "<empty>")]
    [InlineData("", "<empty>")]
    [InlineData("short", "***")]
    public void Masks_short_and_empty_values(string? input, string expected) =>
        Assert.Equal(expected, SecretMasker.Mask(input));

    [Fact]
    public void Long_values_never_leak_the_middle()
    {
        var secret = "AAAAAAAA" + new string('x', 40) + "ZZZZ";

        var masked = SecretMasker.Mask(secret);

        Assert.StartsWith("AAAAAAAA", masked);
        Assert.DoesNotContain(new string('x', 10), masked);
        Assert.Contains("len=52", masked);
    }
}
