using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;

public sealed class Argon2IDService
{
    private const int MemorySizeKiB = 65_536;
    private const int Iterations = 3;
    private const int DegreeOfParallelism = 1;
    private const int SaltSize = 16;
    private const int HashSize = 32;

    private readonly byte[] _pepper;

    public Argon2IDService(IConfiguration configuration)
    {
        var configuredPepper = configuration["Authentication:Pepper"];
        if (string.IsNullOrWhiteSpace(configuredPepper))
        {
            throw new InvalidOperationException(
                "Authentication:Pepper is required. Configure it using ASP.NET Core User Secrets or a secure environment variable.");
        }

        try
        {
            _pepper = Convert.FromBase64String(configuredPepper);
        }
        catch (FormatException exception)
        {
            throw new InvalidOperationException("Authentication:Pepper must be a Base64-encoded random secret.", exception);
        }

        if (_pepper.Length < 32)
        {
            throw new InvalidOperationException("Authentication:Pepper must contain at least 32 random bytes.");
        }
    }

    public async Task<string> HashPasswordAsync(string password)
    {
        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var hash = await DeriveHashAsync(password, salt, MemorySizeKiB, Iterations, DegreeOfParallelism);

        return $"$argon2id$v=19$m={MemorySizeKiB},t={Iterations},p={DegreeOfParallelism}${EncodeBase64(salt)}${EncodeBase64(hash)}";
    }

    public async Task<bool> VerifyPasswordAsync(string password, string encodedHash)
    {
        if (!TryParseHash(encodedHash, out var parameters))
        {
            return false;
        }

        var actualHash = await DeriveHashAsync(
            password,
            parameters.Salt,
            parameters.MemorySizeKiB,
            parameters.Iterations,
            parameters.DegreeOfParallelism);

        return CryptographicOperations.FixedTimeEquals(actualHash, parameters.Hash);
    }

    private async Task<byte[]> DeriveHashAsync(
        string password,
        byte[] salt,
        int memorySizeKiB,
        int iterations,
        int degreeOfParallelism)
    {
        var passwordBytes = Encoding.UTF8.GetBytes(password);
        var pepperedPassword = HMACSHA256.HashData(_pepper, passwordBytes);
        CryptographicOperations.ZeroMemory(passwordBytes);

        try
        {
            using var argon2 = new Argon2id(pepperedPassword)
            {
                Salt = salt,
                MemorySize = memorySizeKiB,
                Iterations = iterations,
                DegreeOfParallelism = degreeOfParallelism
            };

            return await argon2.GetBytesAsync(HashSize);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pepperedPassword);
        }
    }

    private static bool TryParseHash(string encodedHash, out EncodedHash parameters)
    {
        parameters = default;
        var parts = encodedHash.Split('$');
        if (parts.Length != 6 ||
            parts[0].Length != 0 ||
            parts[1] != "argon2id" ||
            parts[2] != "v=19")
        {
            return false;
        }

        var values = parts[3].Split(',');
        if (values.Length != 3 ||
            !TryReadParameter(values[0], "m=", 8_192, 262_144, out var memorySizeKiB) ||
            !TryReadParameter(values[1], "t=", 1, 10, out var iterations) ||
            !TryReadParameter(values[2], "p=", 1, 4, out var degreeOfParallelism))
        {
            return false;
        }

        try
        {
            var salt = DecodeBase64(parts[4]);
            var hash = DecodeBase64(parts[5]);
            if (salt.Length is < 16 or > 64 || hash.Length != HashSize)
            {
                return false;
            }

            parameters = new EncodedHash(salt, hash, memorySizeKiB, iterations, degreeOfParallelism);
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private static bool TryReadParameter(string value, string prefix, int minimum, int maximum, out int result)
    {
        result = 0;
        return value.StartsWith(prefix, StringComparison.Ordinal) &&
            int.TryParse(value.AsSpan(prefix.Length), out result) &&
            result >= minimum &&
            result <= maximum;
    }

    private static string EncodeBase64(byte[] value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static byte[] DecodeBase64(string value)
    {
        var base64 = value.Replace('-', '+').Replace('_', '/');
        return Convert.FromBase64String(base64.PadRight(base64.Length + (4 - base64.Length % 4) % 4, '='));
    }

    private readonly record struct EncodedHash(
        byte[] Salt,
        byte[] Hash,
        int MemorySizeKiB,
        int Iterations,
        int DegreeOfParallelism);
}