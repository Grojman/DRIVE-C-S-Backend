using Microsoft.Data.Sqlite;

public static class FileDataService
{
    private const string CreateFileInfoTableQuery = @"
        CREATE TABLE IF NOT EXISTS FileInfo (
            Id INTEGER PRIMARY KEY AUTOINCREMENT,
            Name TEXT NOT NULL,
            Path TEXT NOT NULL,
            Size INTEGER NOT NULL DEFAULT 0,
            CreatedAt TEXT NOT NULL,
            ModifiedAt TEXT NOT NULL,
            FileType TEXT NOT NULL CHECK (FileType IN ('File', 'Directory'))
        )";
    private const string CreateFileKeysTableQuery = @"
        CREATE TABLE IF NOT EXISTS FileKeys (
            Id INTEGER PRIMARY KEY AUTOINCREMENT,
            FileId INTEGER NOT NULL,
            PrivateKey TEXT NOT NULL,
            FOREIGN KEY (FileId) REFERENCES FileInfo(Id) ON DELETE CASCADE
        )";
    private const string CreateFileKeysIndexQuery = "CREATE INDEX IF NOT EXISTS IX_FileKeys_FileId ON FileKeys (FileId)";

    private const string ReadFileQuery = "SELECT Id, Name, Path, Size, CreatedAt, ModifiedAt, FileType FROM FileInfo WHERE Id = @Id";
    private const string DeleteFileQuery = "DELETE FROM FileInfo WHERE Id = @Id";
    private const string UpdateFileQuery = "UPDATE FileInfo SET Name = @Name, Path = @Path, Size = @Size, CreatedAt = @CreatedAt, ModifiedAt = @ModifiedAt, FileType = @FileType WHERE Id = @Id";
    private const string CreateFileQuery = "INSERT INTO FileInfo (Name, Path, Size, CreatedAt, ModifiedAt, FileType) VALUES (@Name, @Path, @Size, @CreatedAt, @ModifiedAt, @FileType)";
    private const string LastInsertIdQuery = "SELECT last_insert_rowid()";

    private const string ReadKeysQuery = "SELECT PrivateKey FROM FileKeys WHERE FileId = @FileId ORDER BY Id";
    private const string DeleteKeysQuery = "DELETE FROM FileKeys WHERE FileId = @FileId";
    private const string CreateKeyQuery = "INSERT INTO FileKeys (FileId, PrivateKey) VALUES (@FileId, @PrivateKey)";

    private const string DateFormat = "yyyy-MM-dd HH:mm:ss";

    public static void CreateTables()
    {
        var noArgs = new Dictionary<string, string>();
        DataBaseService.Execute(CreateFileInfoTableQuery, noArgs);
        DataBaseService.Execute(CreateFileKeysTableQuery, noArgs);
        DataBaseService.Execute(CreateFileKeysIndexQuery, noArgs);
    }

    public static IEnumerable<FileInfo> GetFilesInDirectory(int directoryId)
    {
        FileInfo? directory = GetFileById(directoryId);

        if (directory == null || directory.FileType != FileType.Directory)
        {
            return Array.Empty<FileInfo>();
        }

        string[] files = FileSystemService.GetFilesAndDirectories(directory.Path);

        List<FileInfo> fileInfos = new List<FileInfo>();
        foreach (var file in files)
        {
            if (!int.TryParse(file, out int fileId))
            {
                continue;
            }

            FileInfo? fileInfo = GetFileById(fileId);

            if (fileInfo != null)
            {
                fileInfos.Add(fileInfo);
            }
        }
        return fileInfos;
    }

    public static FileInfo? GetFileById(int fileId)
    {
        var args = new Dictionary<string, string> { { "@Id", fileId.ToString() } };

        try
        {
            FileInfo fileInfo = DataBaseService.ReadOne(ReadFileQuery, args, MapFileInfo);
            return fileInfo with { PrivateKeys = GetPrivateKeys(fileId) };
        }
        catch (InvalidOperationException)
        {
            return null;
        }
    }

    public static string[] GetPrivateKeys(int fileId)
    {
        var args = new Dictionary<string, string> { { "@FileId", fileId.ToString() } };
        return DataBaseService.ReadMany(ReadKeysQuery, args, reader => reader.GetString(0)).ToArray();
    }

    public static bool DeleteFileInfo(int fileId)
    {
        var args = new Dictionary<string, string> { { "@Id", fileId.ToString() } };
        var keyArgs = new Dictionary<string, string> { { "@FileId", fileId.ToString() } };

        return RunInTransaction(() =>
        {
            // ON DELETE CASCADE ya lo cubre, pero se borra explicitamente por si foreign_keys esta desactivado
            DataBaseService.Execute(DeleteKeysQuery, keyArgs);
            DataBaseService.Execute(DeleteFileQuery, args);
        });
    }

    public static bool UpdateFileInfo(FileInfo fileInfo)
    {
        var args = BuildFileArgs(fileInfo);
        args.Add("@Id", fileInfo.Id.ToString());

        return RunInTransaction(() =>
        {
            DataBaseService.Execute(UpdateFileQuery, args);
            ReplacePrivateKeys(fileInfo.Id, fileInfo.PrivateKeys);
        });
    }

    public static bool CreateFileInfo(FileInfo fileInfo)
    {
        var args = BuildFileArgs(fileInfo);

        return RunInTransaction(() =>
        {
            DataBaseService.Execute(CreateFileQuery, args);
            int fileId = DataBaseService.ReadOne<int>(LastInsertIdQuery, new Dictionary<string, string>());
            ReplacePrivateKeys(fileId, fileInfo.PrivateKeys);
        });
    }

    public static int GetFileInfoByNamePath(string name, string path)
    {
        var query = "SELECT Id FROM FileInfo WHERE Name = @Name AND Path = @Path";
        var args = new Dictionary<string, string>
        {
            { "@Name", name },
            { "@Path", path }
        };

        try
        {
            return DataBaseService.ReadOne<int>(query, args);
        }
        catch (InvalidOperationException)
        {
            return -1; // Return -1 if no result is found
        }
    }

    private static void ReplacePrivateKeys(int fileId, string[]? privateKeys)
    {
        DataBaseService.Execute(DeleteKeysQuery, new Dictionary<string, string> { { "@FileId", fileId.ToString() } });

        foreach (var privateKey in privateKeys ?? Array.Empty<string>())
        {
            DataBaseService.Execute(CreateKeyQuery, new Dictionary<string, string>
            {
                { "@FileId", fileId.ToString() },
                { "@PrivateKey", privateKey }
            });
        }
    }

    private static Dictionary<string, string> BuildFileArgs(FileInfo fileInfo)
    {
        return new Dictionary<string, string>
        {
            { "@Name", fileInfo.Name },
            { "@Path", fileInfo.Path },
            { "@Size", fileInfo.Size.ToString() },
            { "@CreatedAt", fileInfo.CreatedAt.ToString(DateFormat) },
            { "@ModifiedAt", fileInfo.ModifiedAt.ToString(DateFormat) },
            { "@FileType", fileInfo.FileType.ToString() }
        };
    }

    private static FileInfo MapFileInfo(SqliteDataReader reader)
    {
        return new FileInfo(
            reader.GetInt32(0),
            reader.GetString(1),
            reader.GetString(2),
            reader.GetInt64(3),
            Array.Empty<string>(),
            DateTime.Parse(reader.GetString(4)),
            DateTime.Parse(reader.GetString(5)),
            Enum.Parse<FileType>(reader.GetString(6))
        );
    }

    // Las claves y el FileInfo deben guardarse juntos o no guardarse
    private static bool RunInTransaction(Action action)
    {
        var noArgs = new Dictionary<string, string>();
        try
        {
            DataBaseService.Execute("BEGIN", noArgs);
            action();
            DataBaseService.Execute("COMMIT", noArgs);
            return true;
        }
        catch (Exception)
        {
            try { DataBaseService.Execute("ROLLBACK", noArgs); } catch (Exception) { }
            return false;
        }
    }
}
