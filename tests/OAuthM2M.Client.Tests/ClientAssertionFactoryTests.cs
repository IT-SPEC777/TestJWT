using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using OAuthM2M.Client.Security;

namespace OAuthM2M.Client.Tests;

public sealed class ClientAssertionFactoryTests : IDisposable
{
    private static readonly DateTimeOffset Now = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    private readonly TempDir _dir = new();
    private readonly RSA _rsa;
    private readonly ClientAssertionFactory _factory;
    private readonly OAuthClientOptions _options;

    public ClientAssertionFactoryTests()
    {
        var (path, rsa) = TestKeys.WritePrivateKey(_dir);
        _rsa = rsa;
        _options = TestKeys.JwtOptions(path);
        _factory = new ClientAssertionFactory(TestKeys.Wrap(_options), new FixedTimeProvider(Now));
    }

    public void Dispose()
    {
        _factory.Dispose();
        _rsa.Dispose();
        _dir.Dispose();
    }

    [Fact]
    public void Header_has_RS256_typ_and_kid()
    {
        var jwt = new JwtSecurityTokenHandler().ReadJwtToken(_factory.Create());

        Assert.Equal("RS256", jwt.Header.Alg);
        Assert.Equal("JWT", jwt.Header.Typ);
        Assert.Equal("key-1", jwt.Header.Kid);
    }

    [Fact]
    public void Payload_has_required_claims()
    {
        var jwt = new JwtSecurityTokenHandler().ReadJwtToken(_factory.Create());

        Assert.Equal("my-service", jwt.Issuer);
        Assert.Equal("my-service", jwt.Subject);
        Assert.Equal(TestKeys.TokenEndpoint, Assert.Single(jwt.Audiences));
        Assert.True(Guid.TryParse(jwt.Id, out _), "jti должен быть GUID");
    }

    [Fact]
    public void Lifetime_matches_settings()
    {
        var jwt = new JwtSecurityTokenHandler().ReadJwtToken(_factory.Create());

        Assert.Equal(Now.UtcDateTime, jwt.ValidFrom);
        Assert.Equal(Now.UtcDateTime.AddSeconds(120), jwt.ValidTo);
    }

    [Fact]
    public void Jti_is_unique_per_call()
    {
        var handler = new JwtSecurityTokenHandler();
        var first = handler.ReadJwtToken(_factory.Create()).Id;
        var second = handler.ReadJwtToken(_factory.Create()).Id;

        Assert.NotEqual(first, second);
    }

    [Fact]
    public void Signature_is_valid_for_public_key()
    {
        using var publicKey = RSA.Create();
        publicKey.ImportRSAPublicKey(_rsa.ExportRSAPublicKey(), out _);

        var parameters = new TokenValidationParameters
        {
            ValidIssuer = "my-service",
            ValidAudience = TestKeys.TokenEndpoint,
            IssuerSigningKey = new RsaSecurityKey(publicKey) { KeyId = "key-1" },
            ValidateLifetime = false   // время зафиксировано в 2026-01-01
        };

        new JwtSecurityTokenHandler().ValidateToken(_factory.Create(), parameters, out var validated);

        Assert.NotNull(validated);
    }

    [Fact]
    public void Explicit_audience_overrides_token_endpoint()
    {
        _options.Audience = "https://auth.example.com/realms/demo";

        var jwt = new JwtSecurityTokenHandler().ReadJwtToken(_factory.Create());

        Assert.Equal("https://auth.example.com/realms/demo", Assert.Single(jwt.Audiences));
    }

    [Fact]
    public void Missing_key_file_fails_on_first_use()
    {
        var options = TestKeys.JwtOptions(_dir.File("nope.pem"));
        using var factory = new ClientAssertionFactory(TestKeys.Wrap(options), TimeProvider.System);

        Assert.Throws<FileNotFoundException>(() => factory.Create());
    }
}
