namespace OAuthM2M.Client.Tests;

public sealed class OptionsValidatorTests
{
    private static readonly OAuthClientOptionsValidator Validator = new();

    private static OAuthClientOptions ValidJwt() => TestKeys.JwtOptions("/keys/private.pem");

    private static OAuthClientOptions ValidMtls() => new()
    {
        AuthMethod = ClientAuthMethod.TlsClientAuth,
        TokenEndpoint = TestKeys.TokenEndpoint,
        ClientId = "my-service",
        ClientCertificatePath = "/certs/client.pfx"
    };

    [Fact]
    public void Valid_private_key_jwt_options_pass() =>
        Assert.True(Validator.Validate(null, ValidJwt()).Succeeded);

    [Fact]
    public void Valid_mtls_options_pass() =>
        Assert.True(Validator.Validate(null, ValidMtls()).Succeeded);

    [Fact]
    public void Missing_basics_are_reported()
    {
        var result = Validator.Validate(null, new OAuthClientOptions());

        Assert.True(result.Failed);
        Assert.Contains(result.Failures!, f => f.Contains("TokenEndpoint"));
        Assert.Contains(result.Failures!, f => f.Contains("ClientId"));
        Assert.Contains(result.Failures!, f => f.Contains("KeyId"));
        Assert.Contains(result.Failures!, f => f.Contains("PrivateKeyPath"));
    }

    [Theory]
    [InlineData(59)]
    [InlineData(301)]
    public void Assertion_lifetime_must_be_60_to_300(int seconds)
    {
        var o = ValidJwt();
        o.AssertionLifetimeSeconds = seconds;

        Assert.Contains(Validator.Validate(null, o).Failures!, f => f.Contains("AssertionLifetimeSeconds"));
    }

    [Theory]
    [InlineData(60)]
    [InlineData(300)]
    public void Assertion_lifetime_bounds_are_allowed(int seconds)
    {
        var o = ValidJwt();
        o.AssertionLifetimeSeconds = seconds;

        Assert.True(Validator.Validate(null, o).Succeeded);
    }

    [Fact]
    public void Plain_http_is_rejected_for_remote_hosts()
    {
        var o = ValidJwt();
        o.TokenEndpoint = "http://auth.example.com/token";

        Assert.True(Validator.Validate(null, o).Failed);
    }

    [Fact]
    public void Plain_http_is_allowed_for_localhost_in_private_key_jwt_mode()
    {
        var o = ValidJwt();
        o.TokenEndpoint = "http://localhost:8080/realms/demo/protocol/openid-connect/token";

        Assert.True(Validator.Validate(null, o).Succeeded);
    }

    [Fact]
    public void Mtls_requires_https_even_on_localhost()
    {
        var o = ValidMtls();
        o.TokenEndpoint = "http://localhost:8080/token";

        Assert.True(Validator.Validate(null, o).Failed);
    }

    [Fact]
    public void Mtls_requires_certificate_path()
    {
        var o = ValidMtls();
        o.ClientCertificatePath = null;

        Assert.Contains(Validator.Validate(null, o).Failures!, f => f.Contains("ClientCertificatePath"));
    }
}
