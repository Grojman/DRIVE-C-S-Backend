using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

public record AuthTokens(string AccessToken, string RefreshToken);

// Token de acceso: JWT firmado con HS256, de vida corta y sin estado en el servidor.
// Token de refresco: valor aleatorio opaco guardado (hasheado) en la base de datos, de vida larga y de un solo uso.
public static class JwtService
{
    private const string Algorithm = "HS256";
    private const string DateFormat = "yyyy-MM-dd HH:mm:ss";

    private static byte[] _secret = RandomNumberGenerator.GetBytes(64);
    private static string _issuer = "DRIVE-C-S-Backend";
    private static TimeSpan _accessTokenLifetime = TimeSpan.FromMinutes(15);
    private static TimeSpan _refreshTokenLifetime = TimeSpan.FromDays(7);

    private const string CreateRefreshTokensTableQuery = @"
        CREATE TABLE IF NOT EXISTS RefreshTokens (
            Id INTEGER PRIMARY KEY AUTOINCREMENT,
            UserId INTEGER NOT NULL,
            TokenHash TEXT NOT NULL UNIQUE,
            ExpiresAt TEXT NOT NULL,
            FOREIGN KEY (UserId) REFERENCES Users(Id) ON DELETE CASCADE
        )";
    private const string CreateRefreshTokenQuery = "INSERT INTO RefreshTokens (UserId, TokenHash, ExpiresAt) VALUES (@UserId, @TokenHash, @ExpiresAt)";
    private const string ReadRefreshTokenQuery = "SELECT UserId, ExpiresAt FROM RefreshTokens WHERE TokenHash = @TokenHash";
    private const string DeleteRefreshTokenQuery = "DELETE FROM RefreshTokens WHERE TokenHash = @TokenHash";
    private const string DeleteExpiredRefreshTokensQuery = "DELETE FROM RefreshTokens WHERE ExpiresAt < @Now";

    private static readonly object RefreshLock = new();

    // Si no hay "Jwt:Secret" en la configuración se usa uno aleatorio: los tokens de acceso dejan de ser
    // válidos al reiniciar el servidor, pero el cliente los renueva con el token de refresco (que sigue en la BD).
    public static void Configure(IConfiguration configuration)
    {
        var secret = configuration["Jwt:Secret"];
        if (!string.IsNullOrEmpty(secret))
        {
            var bytes = Encoding.UTF8.GetBytes(secret);
            if (bytes.Length < 32) throw new InvalidOperationException("Jwt:Secret must be at least 32 bytes long");
            _secret = bytes;
        }
        else
        {
            Console.WriteLine("Jwt:Secret not configured, using a random secret for this run");
        }

        _issuer = configuration["Jwt:Issuer"] ?? _issuer;
        if (int.TryParse(configuration["Jwt:AccessTokenMinutes"], out int minutes)) _accessTokenLifetime = TimeSpan.FromMinutes(minutes);
        if (int.TryParse(configuration["Jwt:RefreshTokenDays"], out int days)) _refreshTokenLifetime = TimeSpan.FromDays(days);
    }

    public static void CreateTable()
    {
        var noArgs = new Dictionary<string, string>();
        DataBaseService.Execute(CreateRefreshTokensTableQuery, noArgs);
        DataBaseService.Execute(DeleteExpiredRefreshTokensQuery, new Dictionary<string, string> { { "@Now", DateTime.UtcNow.ToString(DateFormat, CultureInfo.InvariantCulture) } });
    }

    public static AuthTokens IssueTokens(int userId) => new(CreateAccessToken(userId), CreateRefreshToken(userId));

    public static string CreateTotpChallengeToken(int userId) =>
        CreateAccessToken(userId, "totp", TimeSpan.FromMinutes(5));

    public static bool TryValidateTotpChallengeToken(string token, out int userId) =>
        TryValidateToken(token, "totp", out userId);

    public static byte[] DerivePurposeKey(string purpose) =>
        HMACSHA256.HashData(_secret, Encoding.UTF8.GetBytes(purpose));

    // Intercambia un token de refresco por un par nuevo. El usado se borra (rotación) para que no pueda reutilizarse.
    public static AuthTokens? Refresh(string refreshToken)
    {
        var hash = Hash(refreshToken);
        var args = new Dictionary<string, string> { { "@TokenHash", hash } };

        lock (RefreshLock)
        {
            (int userId, DateTime expiresAt) stored;
            try
            {
                stored = DataBaseService.ReadOne(ReadRefreshTokenQuery, args,
                    r => (r.GetInt32(0), DateTime.ParseExact(r.GetString(1), DateFormat, CultureInfo.InvariantCulture)));
            }
            catch (InvalidOperationException)
            {
                return null;
            }

            DataBaseService.Execute(DeleteRefreshTokenQuery, args);

            if (stored.expiresAt < DateTime.UtcNow) return null;

            return IssueTokens(stored.userId);
        }
    }

    public static void RevokeRefreshToken(string refreshToken)
    {
        DataBaseService.Execute(DeleteRefreshTokenQuery, new Dictionary<string, string> { { "@TokenHash", Hash(refreshToken) } });
    }

    public static void RevokeAllRefreshTokens(int userId)
    {
        DataBaseService.Execute(
            "DELETE FROM RefreshTokens WHERE UserId = @UserId",
            new Dictionary<string, string> { ["@UserId"] = userId.ToString() });
    }

    public static bool TryValidateAccessToken(string token, out int userId)
        => TryValidateToken(token, "access", out userId, allowLegacyAccessToken: true);

    private static bool TryValidateToken(
        string token,
        string expectedUse,
        out int userId,
        bool allowLegacyAccessToken = false)
    {
        userId = -1;

        var parts = token.Split('.');
        if (parts.Length != 3) return false;

        try
        {
            var expected = Sign($"{parts[0]}.{parts[1]}");
            var received = Base64UrlDecode(parts[2]);
            if (!CryptographicOperations.FixedTimeEquals(expected, received)) return false;

            // Se comprueba el algoritmo para no aceptar tokens con "alg": "none" u otros
            using var header = JsonDocument.Parse(Base64UrlDecode(parts[0]));
            if (!header.RootElement.TryGetProperty("alg", out var alg) || alg.GetString() != Algorithm) return false;

            using var payload = JsonDocument.Parse(Base64UrlDecode(parts[1]));
            var claims = payload.RootElement;

            if (!claims.TryGetProperty("iss", out var iss) || iss.GetString() != _issuer) return false;
            if (!claims.TryGetProperty("exp", out var exp) || exp.GetInt64() < DateTimeOffset.UtcNow.ToUnixTimeSeconds()) return false;
            if (!claims.TryGetProperty("sub", out var sub) || !int.TryParse(sub.GetString(), out userId)) return false;
            if (claims.TryGetProperty("use", out var use))
            {
                if (use.GetString() != expectedUse) return false;
            }
            else if (!allowLegacyAccessToken)
            {
                return false;
            }

            return true;
        }
        catch (Exception e) when (e is FormatException or JsonException or InvalidOperationException)
        {
            userId = -1;
            return false;
        }
    }

    private static string CreateAccessToken(int userId, string use = "access", TimeSpan? lifetime = null)
    {
        var now = DateTimeOffset.UtcNow;
        var header = JsonSerializer.Serialize(new Dictionary<string, object> { { "alg", Algorithm }, { "typ", "JWT" } });
        var payload = JsonSerializer.Serialize(new Dictionary<string, object>
        {
            { "sub", userId.ToString() },
            { "iss", _issuer },
            { "iat", now.ToUnixTimeSeconds() },
            { "exp", now.Add(lifetime ?? _accessTokenLifetime).ToUnixTimeSeconds() },
            { "use", use }
        });

        var unsigned = $"{Base64UrlEncode(Encoding.UTF8.GetBytes(header))}.{Base64UrlEncode(Encoding.UTF8.GetBytes(payload))}";
        return $"{unsigned}.{Base64UrlEncode(Sign(unsigned))}";
    }

    private static string CreateRefreshToken(int userId)
    {
        var token = Base64UrlEncode(RandomNumberGenerator.GetBytes(64));
        DataBaseService.Execute(CreateRefreshTokenQuery, new Dictionary<string, string>
        {
            { "@UserId", userId.ToString() },
            { "@TokenHash", Hash(token) },
            { "@ExpiresAt", DateTime.UtcNow.Add(_refreshTokenLifetime).ToString(DateFormat, CultureInfo.InvariantCulture) }
        });
        return token;
    }

    private static byte[] Sign(string data) => HMACSHA256.HashData(_secret, Encoding.UTF8.GetBytes(data));

    // En la BD solo se guarda el hash: si se filtra la base de datos no se pueden usar los tokens
    private static string Hash(string token) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(token)));

    private static string Base64UrlEncode(byte[] data) =>
        Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static byte[] Base64UrlDecode(string data)
    {
        var s = data.Replace('-', '+').Replace('_', '/');
        return Convert.FromBase64String(s.PadRight(s.Length + (4 - s.Length % 4) % 4, '='));
    }
}
