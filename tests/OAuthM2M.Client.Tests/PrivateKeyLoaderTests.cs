using System.Security.Cryptography;
using OAuthM2M.Client.Security;

namespace OAuthM2M.Client.Tests;

public sealed class PrivateKeyLoaderTests
{
    [Fact]
    public void Loads_plain_pkcs8_pem()
    {
        using var dir = new TempDir();
        var (path, source) = TestKeys.WritePrivateKey(dir);
        using var keyOwner = source;

        using var loaded = PrivateKeyLoader.Load(path);

        Assert.Equal(2048, loaded.KeySize);
    }

    [Fact]
    public void Loads_encrypted_pem_with_password()
    {
        using var dir = new TempDir();
        var (path, source) = TestKeys.WritePrivateKey(dir, password: "s3cret");
        using var keyOwner = source;

        using var loaded = PrivateKeyLoader.Load(path, "s3cret");

        Assert.Equal(2048, loaded.KeySize);
    }

    [Fact]
    public void Wrong_password_fails()
    {
        using var dir = new TempDir();
        var (path, source) = TestKeys.WritePrivateKey(dir, password: "s3cret");
        using var keyOwner = source;

        Assert.ThrowsAny<CryptographicException>(() => PrivateKeyLoader.Load(path, "wrong"));
    }

    [Fact]
    public void Missing_file_throws_FileNotFound()
    {
        using var dir = new TempDir();

        Assert.Throws<FileNotFoundException>(() => PrivateKeyLoader.Load(dir.File("missing.pem")));
    }

    [Fact]
    public void Rejects_keys_shorter_than_2048_bits()
    {
        using var dir = new TempDir();
        var (path, source) = TestKeys.WritePrivateKey(dir, bits: 1024);
        using var keyOwner = source;

        Assert.Throws<CryptographicException>(() => PrivateKeyLoader.Load(path));
    }
}
