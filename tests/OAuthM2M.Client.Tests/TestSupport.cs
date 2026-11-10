using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Options;
using OAuthM2M.Client;

namespace OAuthM2M.Client.Tests;

/// <summary>Временный каталог, удаляемый после теста.</summary>
internal sealed class TempDir : IDisposable
{
    public TempDir()
    {
        Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "oauth-m2m-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path);
    }

    public string Path { get; }

    public string File(string name) => System.IO.Path.Combine(Path, name);

    public void Dispose()
    {
        try
        {
            Directory.Delete(Path, recursive: true);
        }
        catch (IOException)
        {
            // best effort
        }
    }
}

internal static class TestKeys
{
    public const string TokenEndpoint = "https://auth.example.com/realms/demo/protocol/openid-connect/token";

    /// <summary>Создаёт PKCS#8 PEM-ключ, возвращает путь и RSA (для проверки подписи).</summary>
    public static (string Path, RSA Rsa) WritePrivateKey(TempDir dir, int bits = 2048, string? password = null, string name = "private.pem")
    {
        var rsa = RSA.Create(bits);
        var pem = password is null
            ? rsa.ExportPkcs8PrivateKeyPem()
            : rsa.ExportEncryptedPkcs8PrivateKeyPem(
                password,
                new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 10_000));
        var path = dir.File(name);
        File.WriteAllText(path, pem);
        return (path, rsa);
    }

    /// <summary>Самоподписанный сертификат с ключом: PFX и PEM (crt + key).</summary>
    public static (string Pfx, string Crt, string Key) WriteSelfSignedCertificate(TempDir dir, string pfxPassword = "pfx-pass")
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=my-service", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));

        var pfx = dir.File("client.pfx");
        var crt = dir.File("client.crt");
        var key = dir.File("client.key");
        File.WriteAllBytes(pfx, cert.Export(X509ContentType.Pfx, pfxPassword));
        File.WriteAllText(crt, cert.ExportCertificatePem());
        File.WriteAllText(key, rsa.ExportPkcs8PrivateKeyPem());
        return (pfx, crt, key);
    }

    public static OAuthClientOptions JwtOptions(string keyPath) => new()
    {
        TokenEndpoint = TokenEndpoint,
        ClientId = "my-service",
        KeyId = "key-1",
        PrivateKeyPath = keyPath,
        AssertionLifetimeSeconds = 120
    };

    public static IOptions<OAuthClientOptions> Wrap(OAuthClientOptions o) => Microsoft.Extensions.Options.Options.Create(o);
}

/// <summary>Фиксированное время для детерминированных проверок exp/nbf.</summary>
internal sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
{
    public override DateTimeOffset GetUtcNow() => now;
}
