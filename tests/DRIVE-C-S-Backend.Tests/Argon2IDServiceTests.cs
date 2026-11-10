using Microsoft.Extensions.Configuration;
using System.Security.Cryptography;
using System.Text;

namespace DRIVE_C_S_Backend.Tests;

public sealed class Argon2IDServiceTests
{
    private static Argon2IDService CreateService() =>
        new(new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Authentication:Pepper"] = Convert.ToBase64String(Enumerable.Repeat((byte)0xA5, 32).ToArray())
            })
            .Build());

    [Fact]
    public async Task HashesUseIndependentSaltsAndVerifyOnlyTheOriginalPassword()
    {
        var service = CreateService();

        var firstHash = await service.HashPasswordAsync("correct horse battery staple");
        var secondHash = await service.HashPasswordAsync("correct horse battery staple");

        Assert.StartsWith("$argon2id$v=19$m=65536,t=3,p=1$", firstHash);
        Assert.NotEqual(firstHash, secondHash);
        Assert.True(await service.VerifyPasswordAsync("correct horse battery staple", firstHash));
        Assert.False(await service.VerifyPasswordAsync("wrong password", firstHash));
    }

    [Fact]
    public async Task RejectsMalformedEncodedHash()
    {
        Assert.False(await CreateService().VerifyPasswordAsync("password", "not-an-argon2-hash"));
    }

    [Fact]
    public void RequiresAConfiguredPepper()
    {
        var configuration = new ConfigurationBuilder().Build();

        Assert.Throws<InvalidOperationException>(() => new Argon2IDService(configuration));
    }

    [Fact]
    public void LegacyVerifierMatchesTheOldFrontendDerivationOnly()
    {
        const string password = "legacy test password";
        var md5Hex = Convert.ToHexString(MD5.HashData(Encoding.UTF8.GetBytes(password))).ToLowerInvariant();
        var legacyHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(md5Hex))).ToLowerInvariant();
        var legacyUser = new UserService.UserDB(
            1,
            "legacy-user",
            legacyHash[..32],
            "legacy",
            "public-key",
            "encrypted-private-key",
            null,
            null);

        Assert.True(UserService.IsLegacyPasswordValid(legacyUser, password));
        Assert.False(UserService.IsLegacyPasswordValid(legacyUser, "different password"));
    }
}
