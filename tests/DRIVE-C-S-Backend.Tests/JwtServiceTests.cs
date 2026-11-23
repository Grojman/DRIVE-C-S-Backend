using Microsoft.Extensions.Configuration;

namespace DRIVE_C_S_Backend.Tests;

public sealed class JwtServiceTests
{
    [Fact]
    public void TotpChallengeCannotBeUsedAsAnAccessToken()
    {
        JwtService.Configure(new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Jwt:Secret"] = Convert.ToBase64String(Enumerable.Repeat((byte)0x5A, 48).ToArray())
            })
            .Build());

        var challenge = JwtService.CreateTotpChallengeToken(42);

        Assert.True(JwtService.TryValidateTotpChallengeToken(challenge, out var challengeUserId));
        Assert.Equal(42, challengeUserId);
        Assert.False(JwtService.TryValidateAccessToken(challenge, out _));
    }
}
