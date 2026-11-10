using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;
using OAuthM2M.Client.Security;

namespace OAuthM2M.Client.Tests;

public sealed class JwksExporterTests
{
    [Fact]
    public void Exports_public_key_only_with_kid()
    {
        using var dir = new TempDir();
        var (path, rsa) = TestKeys.WritePrivateKey(dir);
        using var keyOwner = rsa;

        var json = JwksExporter.ExportPublicJwks(TestKeys.JwtOptions(path));

        using var doc = JsonDocument.Parse(json);
        var key = doc.RootElement.GetProperty("keys")[0];
        Assert.Equal("RSA", key.GetProperty("kty").GetString());
        Assert.Equal("RS256", key.GetProperty("alg").GetString());
        Assert.Equal("sig", key.GetProperty("use").GetString());
        Assert.Equal("key-1", key.GetProperty("kid").GetString());

        var expected = rsa.ExportParameters(false);
        Assert.Equal(Base64UrlEncoder.Encode(expected.Modulus!), key.GetProperty("n").GetString());
        Assert.Equal(Base64UrlEncoder.Encode(expected.Exponent!), key.GetProperty("e").GetString());

        foreach (var privateField in new[] { "d", "p", "q", "dp", "dq", "qi" })
        {
            Assert.False(key.TryGetProperty(privateField, out _), $"в JWKS не должно быть поля {privateField}");
        }
    }

    [Fact]
    public void Requires_key_id()
    {
        using var dir = new TempDir();
        var (path, rsa) = TestKeys.WritePrivateKey(dir);
        using var keyOwner = rsa;
        var options = TestKeys.JwtOptions(path);
        options.KeyId = null;

        Assert.Throws<InvalidOperationException>(() => JwksExporter.ExportPublicJwks(options));
    }
}
