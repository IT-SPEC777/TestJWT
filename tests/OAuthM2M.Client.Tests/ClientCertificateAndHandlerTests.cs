using System.Security.Cryptography;
using OAuthM2M.Client.Security;
using OAuthM2M.Client.Transport;

namespace OAuthM2M.Client.Tests;

public sealed class ClientCertificateAndHandlerTests
{
    private static OAuthClientOptions MtlsOptions(string path) => new()
    {
        AuthMethod = ClientAuthMethod.TlsClientAuth,
        TokenEndpoint = TestKeys.TokenEndpoint,
        ClientId = "my-service",
        ClientCertificatePath = path
    };

    [Fact]
    public void Loads_pfx_with_private_key()
    {
        using var dir = new TempDir();
        var (pfx, _, _) = TestKeys.WriteSelfSignedCertificate(dir, "pfx-pass");
        var options = MtlsOptions(pfx);
        options.ClientCertificatePassword = "pfx-pass";

        using var cert = ClientCertificateLoader.Load(options);

        Assert.True(cert.HasPrivateKey);
        Assert.Equal("CN=my-service", cert.Subject);
    }

    [Fact]
    public void Loads_pem_pair_with_private_key()
    {
        using var dir = new TempDir();
        var (_, crt, key) = TestKeys.WriteSelfSignedCertificate(dir);
        var options = MtlsOptions(crt);
        options.ClientCertificateKeyPath = key;

        using var cert = ClientCertificateLoader.Load(options);

        Assert.True(cert.HasPrivateKey);
    }

    [Fact]
    public void Pem_certificate_without_key_path_is_rejected()
    {
        using var dir = new TempDir();
        var (_, crt, _) = TestKeys.WriteSelfSignedCertificate(dir);

        Assert.Throws<InvalidOperationException>(() => ClientCertificateLoader.Load(MtlsOptions(crt)));
    }

    [Fact]
    public void Missing_certificate_file_throws()
    {
        using var dir = new TempDir();

        Assert.Throws<FileNotFoundException>(() => ClientCertificateLoader.Load(MtlsOptions(dir.File("none.pfx"))));
    }

    [Fact]
    public void Wrong_pfx_password_fails()
    {
        using var dir = new TempDir();
        var (pfx, _, _) = TestKeys.WriteSelfSignedCertificate(dir, "pfx-pass");
        var options = MtlsOptions(pfx);
        options.ClientCertificatePassword = "wrong";

        Assert.ThrowsAny<CryptographicException>(() => ClientCertificateLoader.Load(options));
    }

    [Fact]
    public void Mtls_handler_carries_client_certificate()
    {
        using var dir = new TempDir();
        var (pfx, _, _) = TestKeys.WriteSelfSignedCertificate(dir, "pfx-pass");
        var options = MtlsOptions(pfx);
        options.ClientCertificatePassword = "pfx-pass";

        using var handler = HttpHandlerFactory.Create(options);

        Assert.Equal(1, handler.SslOptions.ClientCertificates?.Count);
    }

    [Fact]
    public void PrivateKeyJwt_handler_has_no_client_certificate()
    {
        using var handler = HttpHandlerFactory.Create(TestKeys.JwtOptions("/unused.pem"));

        Assert.True(handler.SslOptions.ClientCertificates is null or { Count: 0 });
    }

    [Fact]
    public void Custom_server_ca_installs_validation_callback()
    {
        using var dir = new TempDir();
        var (_, crt, _) = TestKeys.WriteSelfSignedCertificate(dir);
        var options = TestKeys.JwtOptions("/unused.pem");
        options.ServerCaCertificatePath = crt;

        using var handler = HttpHandlerFactory.Create(options);

        Assert.NotNull(handler.SslOptions.RemoteCertificateValidationCallback);
    }

    [Fact]
    public void Missing_server_ca_file_throws()
    {
        using var dir = new TempDir();
        var options = TestKeys.JwtOptions("/unused.pem");
        options.ServerCaCertificatePath = dir.File("ca.crt");

        Assert.Throws<FileNotFoundException>(() => HttpHandlerFactory.Create(options));
    }
}
