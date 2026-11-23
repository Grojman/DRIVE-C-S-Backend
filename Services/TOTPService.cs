using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.WebUtilities;
using QRCoder;

public static class TOTPService
{
    public const string TrustedCookieName = "drive_totp_trusted";
    public static readonly TimeSpan TrustedDeviceLifetime = TimeSpan.FromDays(30);
    private const int CodeLength = 6;
    private const int StepSeconds = 30;
    private const string Issuer = "CriptoNube";
    private static readonly object DatabaseLock = new();
    private static byte[]? _encryptionKey;

    /// <summary>QR image and manual setup key returned during authenticator enrollment.</summary>
    public sealed record Enrollment(string QrCodePng, string ManualKey);
    /// <summary>Opaque device token and its expiration used for the trusted-device cookie.</summary>
    public sealed record TrustedDevice(string Token, DateTimeOffset ExpiresAt);

    public static void Configure(IConfiguration configuration)
    {
        var configuredKey = configuration["TOTP:EncryptionKey"];
        if (!string.IsNullOrEmpty(configuredKey))
        {
            _encryptionKey = Convert.FromBase64String(configuredKey);
            if (_encryptionKey.Length != 32)
            {
                throw new InvalidOperationException("TOTP:EncryptionKey must be a Base64-encoded 32-byte key.");
            }
        }
        else if (!string.IsNullOrEmpty(configuration["Jwt:Secret"]))
        {
            _encryptionKey = JwtService.DerivePurposeKey("DRIVE-C-S/TOTP-secret-encryption/v1");
        }
        else
        {
            _encryptionKey = null;
        }
    }

    public static void CreateTables()
    {
        DataBaseService.Execute(
            @"CREATE TABLE IF NOT EXISTS UserTOTP (
                UserId INTEGER PRIMARY KEY,
                Secret TEXT NULL,
                PendingSecret TEXT NULL,
                Enabled INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (UserId) REFERENCES Users(Id) ON DELETE CASCADE
            )",
            []);
        DataBaseService.Execute(
            @"CREATE TABLE IF NOT EXISTS TrustedTOTPDevices (
                UserId INTEGER NOT NULL,
                TokenHash TEXT NOT NULL UNIQUE,
                ExpiresAt TEXT NOT NULL,
                FOREIGN KEY (UserId) REFERENCES Users(Id) ON DELETE CASCADE
            )",
            []);
        DataBaseService.Execute(
            @"CREATE TABLE IF NOT EXISTS TOTPLoginChallenges (
                TokenHash TEXT PRIMARY KEY,
                UserId INTEGER NOT NULL,
                ExpiresAt TEXT NOT NULL,
                FOREIGN KEY (UserId) REFERENCES Users(Id) ON DELETE CASCADE
            )",
            []);
        DataBaseService.Execute(
            @"CREATE TABLE IF NOT EXISTS TOTPFailures (
                UserId INTEGER PRIMARY KEY,
                Failures INTEGER NOT NULL,
                LockedUntil TEXT NULL,
                FOREIGN KEY (UserId) REFERENCES Users(Id) ON DELETE CASCADE
            )",
            []);
    }

    public static bool IsEnabled(int userId)
    {
        try
        {
            return DataBaseService.ReadOne<int>(
                "SELECT Enabled FROM UserTOTP WHERE UserId = @UserId",
                UserArgs(userId)) == 1;
        }
        catch (InvalidOperationException)
        {
            return false;
        }
    }

    public static Enrollment BeginEnrollment(int userId, string username)
    {
        var secret = RandomNumberGenerator.GetBytes(20);
        var encodedSecret = Base32Encode(secret);
        var encryptedSecret = EncryptSecret(secret);
        DataBaseService.Execute(
            @"INSERT INTO UserTOTP (UserId, PendingSecret, Enabled)
              VALUES (@UserId, @Secret, 0)
              ON CONFLICT(UserId) DO UPDATE SET PendingSecret = @Secret",
            new Dictionary<string, string>
            {
                ["@UserId"] = userId.ToString(),
                ["@Secret"] = encryptedSecret
            });

        var label = Uri.EscapeDataString($"{Issuer}:{username}");
        var uri = $"otpauth://totp/{label}?secret={encodedSecret}&issuer={Uri.EscapeDataString(Issuer)}&algorithm=SHA1&digits=6&period=30";
        using var generator = new QRCodeGenerator();
        using var qrData = generator.CreateQrCode(uri, QRCodeGenerator.ECCLevel.Q);
        var qr = new PngByteQRCode(qrData);
        return new Enrollment(Convert.ToBase64String(qr.GetGraphic(8)), encodedSecret);
    }

    public static bool VerifyEnrollment(int userId, string code)
    {
        var secret = ReadSecret(userId, pending: true);
        if (secret is null || !VerifyAndRecordFailure(userId, secret, code))
        {
            return false;
        }

        var changed = DataBaseService.ExecuteNonQuery(
            @"UPDATE UserTOTP SET Secret = PendingSecret, PendingSecret = NULL, Enabled = 1
              WHERE UserId = @UserId AND PendingSecret IS NOT NULL",
            UserArgs(userId)) == 1;
        if (changed)
        {
            DataBaseService.Execute(
                "DELETE FROM TOTPFailures WHERE UserId = @UserId",
                UserArgs(userId));
        }
        return changed;
    }

    public static bool VerifyLoginCode(int userId, string code)
    {
        var secret = ReadSecret(userId, pending: false);
        return secret is not null && VerifyAndRecordFailure(userId, secret, code);
    }

    public static void StoreLoginChallenge(int userId, string token)
    {
        var expiresAt = DateTimeOffset.UtcNow.AddMinutes(5).ToString("O");
        DataBaseService.Execute(
            "INSERT INTO TOTPLoginChallenges (TokenHash, UserId, ExpiresAt) VALUES (@TokenHash, @UserId, @ExpiresAt)",
            new Dictionary<string, string>
            {
                ["@TokenHash"] = HashToken(token),
                ["@UserId"] = userId.ToString(),
                ["@ExpiresAt"] = expiresAt
            });
        DataBaseService.Execute(
            "DELETE FROM TOTPLoginChallenges WHERE ExpiresAt <= @Now",
            new Dictionary<string, string> { ["@Now"] = DateTimeOffset.UtcNow.ToString("O") });
    }

    public static bool ConsumeLoginChallenge(int userId, string token) =>
        DataBaseService.ExecuteNonQuery(
            "DELETE FROM TOTPLoginChallenges WHERE TokenHash = @TokenHash AND UserId = @UserId AND ExpiresAt > @Now",
            new Dictionary<string, string>
            {
                ["@TokenHash"] = HashToken(token),
                ["@UserId"] = userId.ToString(),
                ["@Now"] = DateTimeOffset.UtcNow.ToString("O")
            }) == 1;

    public static bool IsTrustedDevice(int userId, string? token)
    {
        if (string.IsNullOrEmpty(token))
        {
            return false;
        }
        try
        {
            return DataBaseService.ReadOne<int>(
                "SELECT COUNT(*) FROM TrustedTOTPDevices WHERE UserId = @UserId AND TokenHash = @TokenHash AND ExpiresAt > @Now",
                new Dictionary<string, string>
                {
                    ["@UserId"] = userId.ToString(),
                    ["@TokenHash"] = HashToken(token),
                    ["@Now"] = DateTimeOffset.UtcNow.ToString("O")
                }) > 0;
        }
        catch (InvalidOperationException)
        {
            return false;
        }
    }

    public static TrustedDevice TrustDevice(int userId)
    {
        var token = WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32));
        var expiresAt = DateTimeOffset.UtcNow.Add(TrustedDeviceLifetime);
        DataBaseService.Execute(
            "DELETE FROM TrustedTOTPDevices WHERE ExpiresAt <= @Now",
            new Dictionary<string, string> { ["@Now"] = DateTimeOffset.UtcNow.ToString("O") });
        DataBaseService.Execute(
            "INSERT INTO TrustedTOTPDevices (UserId, TokenHash, ExpiresAt) VALUES (@UserId, @TokenHash, @ExpiresAt)",
            new Dictionary<string, string>
            {
                ["@UserId"] = userId.ToString(),
                ["@TokenHash"] = HashToken(token),
                ["@ExpiresAt"] = expiresAt.ToString("O")
            });
        return new TrustedDevice(token, expiresAt);
    }

    public static void Disable(int userId)
    {
        DataBaseService.Execute(
            "UPDATE UserTOTP SET Secret = NULL, PendingSecret = NULL, Enabled = 0 WHERE UserId = @UserId",
            UserArgs(userId));
        DataBaseService.Execute("DELETE FROM TrustedTOTPDevices WHERE UserId = @UserId", UserArgs(userId));
        DataBaseService.Execute("DELETE FROM TOTPFailures WHERE UserId = @UserId", UserArgs(userId));
    }

    private static byte[]? ReadSecret(int userId, bool pending)
    {
        var column = pending ? "PendingSecret" : "Secret";
        try
        {
            var value = DataBaseService.ReadOne<string>(
                $"SELECT {column} FROM UserTOTP WHERE UserId = @UserId AND {(pending ? "PendingSecret" : "Enabled")} {(pending ? "IS NOT NULL" : "= 1")}",
                UserArgs(userId));
            return DecryptSecret(value);
        }
        catch (InvalidOperationException)
        {
            return null;
        }
    }

    private static bool VerifyAndRecordFailure(int userId, byte[] secret, string code)
    {
        lock (DatabaseLock)
        {
            var now = DateTimeOffset.UtcNow;
            DateTimeOffset? lockedUntil = null;
            var failures = 0;
            try
            {
                (failures, lockedUntil) = DataBaseService.ReadOne(
                    "SELECT Failures, LockedUntil FROM TOTPFailures WHERE UserId = @UserId",
                    UserArgs(userId),
                    reader => (
                        reader.GetInt32(0),
                        reader.IsDBNull(1) || string.IsNullOrEmpty(reader.GetString(1))
                            ? (DateTimeOffset?)null
                            : DateTimeOffset.Parse(reader.GetString(1))));
            }
            catch (InvalidOperationException)
            {
            }

            if (lockedUntil > now)
            {
                return false;
            }

            if (IsValidCode(secret, code, now))
            {
                DataBaseService.Execute("DELETE FROM TOTPFailures WHERE UserId = @UserId", UserArgs(userId));
                return true;
            }

            failures = lockedUntil is not null ? 0 : failures;
            failures++;
            var nextLock = failures >= 5 ? now.AddMinutes(10).ToString("O") : null;
            DataBaseService.Execute(
                @"INSERT INTO TOTPFailures (UserId, Failures, LockedUntil)
                  VALUES (@UserId, @Failures, @LockedUntil)
                  ON CONFLICT(UserId) DO UPDATE SET Failures = @Failures, LockedUntil = @LockedUntil",
                new Dictionary<string, string>
                {
                    ["@UserId"] = userId.ToString(),
                    ["@Failures"] = failures.ToString(),
                    ["@LockedUntil"] = nextLock ?? string.Empty
                });
            return false;
        }
    }

    private static bool IsValidCode(byte[] secret, string? code, DateTimeOffset now)
    {
        if (code is null || code.Length != CodeLength || code.Any(c => c is < '0' or > '9'))
        {
            return false;
        }

        var currentStep = now.ToUnixTimeSeconds() / StepSeconds;
        var supplied = Encoding.ASCII.GetBytes(code);
        for (var offset = -1; offset <= 1; offset++)
        {
            var expected = Encoding.ASCII.GetBytes(CreateCode(secret, currentStep + offset));
            if (CryptographicOperations.FixedTimeEquals(supplied, expected))
            {
                return true;
            }
        }
        return false;
    }

    private static string CreateCode(byte[] secret, long step)
    {
        Span<byte> counter = stackalloc byte[8];
        System.Buffers.Binary.BinaryPrimitives.WriteInt64BigEndian(counter, step);
        var hash = HMACSHA1.HashData(secret, counter);
        var offset = hash[^1] & 0x0f;
        var binary =
            ((hash[offset] & 0x7f) << 24) |
            (hash[offset + 1] << 16) |
            (hash[offset + 2] << 8) |
            hash[offset + 3];
        return (binary % 1_000_000).ToString("D6");
    }

    private static string EncryptSecret(byte[] secret)
    {
        var nonce = RandomNumberGenerator.GetBytes(12);
        var ciphertext = new byte[secret.Length];
        var tag = new byte[16];
        using var aes = new AesGcm(GetEncryptionKey(), tag.Length);
        aes.Encrypt(nonce, secret, ciphertext, tag);
        return Convert.ToBase64String([.. nonce, .. tag, .. ciphertext]);
    }

    private static byte[] DecryptSecret(string encrypted)
    {
        var payload = Convert.FromBase64String(encrypted);
        if (payload.Length < 29)
        {
            throw new CryptographicException("Invalid stored TOTP secret.");
        }
        var secret = new byte[payload.Length - 28];
        using var aes = new AesGcm(GetEncryptionKey(), 16);
        aes.Decrypt(payload.AsSpan(0, 12), payload.AsSpan(28), payload.AsSpan(12, 16), secret);
        return secret;
    }

    private static byte[] GetEncryptionKey() =>
        _encryptionKey ?? throw new InvalidOperationException(
            "TOTP requires a stable Jwt:Secret or a dedicated TOTP:EncryptionKey.");

    private static string HashToken(string token) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(token)));

    private static Dictionary<string, string> UserArgs(int userId) =>
        new() { ["@UserId"] = userId.ToString() };

    private static string Base32Encode(ReadOnlySpan<byte> data)
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        var result = new StringBuilder((data.Length * 8 + 4) / 5);
        var buffer = 0;
        var bitsLeft = 0;
        foreach (var value in data)
        {
            buffer = (buffer << 8) | value;
            bitsLeft += 8;
            while (bitsLeft >= 5)
            {
                result.Append(alphabet[(buffer >> (bitsLeft - 5)) & 31]);
                bitsLeft -= 5;
            }
        }
        if (bitsLeft > 0)
        {
            result.Append(alphabet[(buffer << (5 - bitsLeft)) & 31]);
        }
        return result.ToString();
    }
}