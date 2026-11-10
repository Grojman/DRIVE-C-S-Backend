using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;

public static class UserService
{
    public const int LegacyMigrationDays = 90;
    public const string CurrentKeyKdf = "argon2id-v19-m65536-t3-p1-l16";
    private const string LegacyMigrationStartedSetting = "LegacyPasswordMigrationStartedUtc";

    public record UserDB(
        int Id,
        string Username,
        string Password,
        string PasswordScheme,
        string PublicKey,
        string PrivateKey,
        string? KeySalt,
        string? KeyKdf);

    private const string CreateUsersTableQuery = @"
        CREATE TABLE IF NOT EXISTS Users (
            Id INTEGER PRIMARY KEY AUTOINCREMENT,
            Username TEXT NOT NULL UNIQUE,
            Password TEXT NOT NULL,
            PrivateKey TEXT NOT NULL,
            PublicKey TEXT NOT NULL,
            PasswordScheme TEXT NOT NULL DEFAULT 'legacy',
            KeySalt TEXT NULL,
            KeyKdf TEXT NULL
        )";

    public static void CreateTable()
    {
        DataBaseService.Execute(CreateUsersTableQuery, []);

        var columns = DataBaseService.ReadMany(
            "PRAGMA table_info(Users)",
            [],
            reader => reader.GetString(1)).ToHashSet(StringComparer.OrdinalIgnoreCase);

        if (!columns.Contains("PasswordScheme"))
        {
            DataBaseService.Execute("ALTER TABLE Users ADD COLUMN PasswordScheme TEXT NOT NULL DEFAULT 'legacy'", []);
        }
        if (!columns.Contains("KeySalt"))
        {
            DataBaseService.Execute("ALTER TABLE Users ADD COLUMN KeySalt TEXT NULL", []);
        }
        if (!columns.Contains("KeyKdf"))
        {
            DataBaseService.Execute("ALTER TABLE Users ADD COLUMN KeyKdf TEXT NULL", []);
        }

        DataBaseService.Execute(
            "CREATE TABLE IF NOT EXISTS ApplicationSettings (Key TEXT PRIMARY KEY, Value TEXT NOT NULL)",
            []);
        DataBaseService.Execute(
            "INSERT OR IGNORE INTO ApplicationSettings (Key, Value) VALUES (@Key, @Value)",
            new Dictionary<string, string>
            {
                ["@Key"] = LegacyMigrationStartedSetting,
                ["@Value"] = DateTimeOffset.UtcNow.ToString("O")
            });
    }

    public static IEnumerable<UserDB> GetUsers(int id)
    {
        const string query = "SELECT Id, Username, '', '', PublicKey, PrivateKey, NULL, NULL FROM Users WHERE Id != @id";
        return DataBaseService.ReadMany(query, new Dictionary<string, string> { ["@id"] = id.ToString() }, MapUser);
    }

    public static UserDB? GetUser(string username)
    {
        const string query = "SELECT Id, Username, Password, PasswordScheme, PublicKey, PrivateKey, KeySalt, KeyKdf FROM Users WHERE Username = @username";
        try
        {
            return DataBaseService.ReadOne(
                query,
                new Dictionary<string, string> { ["@username"] = username },
                MapUser);
        }
        catch (InvalidOperationException)
        {
            return null;
        }
    }

    public static bool IsUsernameTaken(string username)
    {
        const string query = "SELECT COUNT(*) FROM Users WHERE Username = @username";
        return DataBaseService.ReadOne<int>(query, new Dictionary<string, string> { ["@username"] = username }) > 0;
    }

    public static bool IsLegacyMigrationOpen()
    {
        var startedAt = DataBaseService.ReadOne<string>(
            "SELECT Value FROM ApplicationSettings WHERE Key = @Key",
            new Dictionary<string, string> { ["@Key"] = LegacyMigrationStartedSetting });
        var deadline = DateTimeOffset.Parse(startedAt).AddDays(LegacyMigrationDays);
        return DateTimeOffset.UtcNow < deadline;
    }

    public static bool IsLegacyPasswordValid(UserDB user, string password)
    {
        if (user.PasswordScheme != "legacy" || user.Password.Length != 32)
        {
            return false;
        }

        var md5Hex = Convert.ToHexString(MD5.HashData(Encoding.UTF8.GetBytes(password))).ToLowerInvariant();
        var legacyHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(md5Hex))).ToLowerInvariant();
        var legacyLoginPassword = legacyHash[..32];

        return CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(user.Password),
            Encoding.UTF8.GetBytes(legacyLoginPassword));
    }

    public static void CreateUser(
        string username,
        string passwordHash,
        string privateKey,
        string publicKey,
        string keySalt,
        string keyKdf)
    {
        const string query = "INSERT INTO Users (Username, Password, PrivateKey, PublicKey, PasswordScheme, KeySalt, KeyKdf) VALUES (@username, @password, @privateKey, @publicKey, 'argon2id', @keySalt, @keyKdf)";
        DataBaseService.Execute(query, new Dictionary<string, string>
        {
            ["@username"] = username,
            ["@password"] = passwordHash,
            ["@privateKey"] = privateKey,
            ["@publicKey"] = publicKey,
            ["@keySalt"] = keySalt,
            ["@keyKdf"] = keyKdf
        });
    }

    public static bool UpgradeLegacyPassword(string username, string legacyPassword, string passwordHash)
    {
        const string query = "UPDATE Users SET Password = @password, PasswordScheme = 'argon2id' WHERE Username = @username AND Password = @legacyPassword AND PasswordScheme = 'legacy'";
        return DataBaseService.ExecuteNonQuery(query, new Dictionary<string, string>
        {
            ["@username"] = username,
            ["@legacyPassword"] = legacyPassword,
            ["@password"] = passwordHash
        }) == 1;
    }

    public static bool ResetLegacyPassword(
        string username,
        string legacyPassword,
        string passwordHash,
        string privateKey,
        string keySalt,
        string keyKdf)
    {
        const string query = "UPDATE Users SET Password = @password, PasswordScheme = 'argon2id', PrivateKey = @privateKey, KeySalt = @keySalt, KeyKdf = @keyKdf WHERE Username = @username AND Password = @legacyPassword AND PasswordScheme = 'legacy'";
        return DataBaseService.ExecuteNonQuery(query, new Dictionary<string, string>
        {
            ["@username"] = username,
            ["@legacyPassword"] = legacyPassword,
            ["@password"] = passwordHash,
            ["@privateKey"] = privateKey,
            ["@keySalt"] = keySalt,
            ["@keyKdf"] = keyKdf
        }) == 1;
    }

    public static bool UpdatePrivateKey(int userId, string privateKey, string keySalt, string keyKdf)
    {
        const string query = "UPDATE Users SET PrivateKey = @privateKey, KeySalt = @keySalt, KeyKdf = @keyKdf WHERE Id = @id AND KeySalt IS NULL";
        return DataBaseService.ExecuteNonQuery(query, new Dictionary<string, string>
        {
            ["@id"] = userId.ToString(),
            ["@privateKey"] = privateKey,
            ["@keySalt"] = keySalt,
            ["@keyKdf"] = keyKdf
        }) == 1;
    }

    private static UserDB MapUser(SqliteDataReader reader) =>
        new(
            reader.GetInt32(0),
            reader.GetString(1),
            reader.GetString(2),
            reader.GetString(3),
            reader.GetString(4),
            reader.GetString(5),
            reader.IsDBNull(6) ? null : reader.GetString(6),
            reader.IsDBNull(7) ? null : reader.GetString(7));
}
