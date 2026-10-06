using Microsoft.Data.Sqlite;

public static class FileDataService
{
    private const string CreateFileInfoTableQuery = @"
        CREATE TABLE IF NOT EXISTS FileInfo (
            Id INTEGER PRIMARY KEY AUTOINCREMENT,
            OwnerId INTEGER NOT NULL,
            Name TEXT NOT NULL,
            Path TEXT NOT NULL,
            Size INTEGER NOT NULL DEFAULT 0,
            CreatedAt TEXT NOT NULL,
            ModifiedAt TEXT NOT NULL,
            FileType TEXT NOT NULL CHECK (FileType IN ('File', 'Directory')),
            FOREIGN KEY (OwnerId) REFERENCES Users(Id) ON DELETE CASCADE
        )";
    private const string CreateFileKeysTableQuery = @"
        CREATE TABLE IF NOT EXISTS FileKeys (
            Id INTEGER PRIMARY KEY AUTOINCREMENT,
            FileId INTEGER NOT NULL,
            PrivateKey TEXT NOT NULL,
            FOREIGN KEY (FileId) REFERENCES FileInfo(Id) ON DELETE CASCADE
        )";
    private const string CreateFileKeysIndexQuery = "CREATE INDEX IF NOT EXISTS IX_FileKeys_FileId ON FileKeys (FileId)";
    private const string CreateFileInfoOwnerIndexQuery = "CREATE INDEX IF NOT EXISTS IX_FileInfo_OwnerId ON FileInfo (OwnerId)";

    private const string ReadFileQuery = "SELECT Id, Name, Path, Size, CreatedAt, ModifiedAt, FileType FROM FileInfo WHERE Id = @Id AND OwnerId = @OwnerId";
    private const string DeleteFileQuery = "DELETE FROM FileInfo WHERE Id = @Id AND OwnerId = @OwnerId";
    private const string UpdateFileQuery = "UPDATE FileInfo SET Name = @Name, Path = @Path, Size = @Size, CreatedAt = @CreatedAt, ModifiedAt = @ModifiedAt, FileType = @FileType WHERE Id = @Id AND OwnerId = @OwnerId";
    private const string CreateFileQuery = "INSERT INTO FileInfo (OwnerId, Name, Path, Size, CreatedAt, ModifiedAt, FileType) VALUES (@OwnerId, @Name, @Path, @Size, @CreatedAt, @ModifiedAt, @FileType)";
    private const string LastInsertIdQuery = "SELECT last_insert_rowid()";

    private const string ReadKeysQuery = "SELECT PrivateKey FROM FileKeys WHERE FileId = @FileId ORDER BY Id";
    private const string DeleteKeysQuery = "DELETE FROM FileKeys WHERE FileId = @FileId";
    private const string CreateKeyQuery = "INSERT INTO FileKeys (FileId, PrivateKey) VALUES (@FileId, @PrivateKey)";

    private const string DateFormat = "yyyy-MM-dd HH:mm:ss";

    private const string SubtreeCondition = "(Path = @Path OR substr(Path, 1, length(@Path) + 1) = @Path || '/')";

    private const string ListPathQuery = "SELECT Id, Name, Path, Size, CreatedAt, ModifiedAt, FileType FROM FileInfo WHERE OwnerId = @OwnerId AND Path = @Path ORDER BY Name";
    private const string FolderExistsQuery = "SELECT COUNT(1) FROM FileInfo WHERE OwnerId = @OwnerId AND Path = @Path AND Name = @Name AND FileType = 'Directory'";
    private const string SubtreeFileIdsQuery = "SELECT Id FROM FileInfo WHERE OwnerId = @OwnerId AND FileType = 'File' AND " + SubtreeCondition;
    private const string DeleteSubtreeQuery = "DELETE FROM FileInfo WHERE OwnerId = @OwnerId AND " + SubtreeCondition;
    private const string MoveSubtreeQuery = "UPDATE FileInfo SET Path = @NewPath || substr(Path, length(@Path) + 1) WHERE OwnerId = @OwnerId AND " + SubtreeCondition;

    public static IEnumerable<FileInfo> GetFilesInPath(int userId, string path)
    {
        var args = new Dictionary<string, string> { { "@OwnerId", userId.ToString() }, { "@Path", path } };
        return DataBaseService.ReadMany(ListPathQuery, args, MapFileInfo)
            .ToList()
            .Select(f => f with { PrivateKeys = GetPrivateKeys(f.Id) });
    }

    public static bool FolderExists(int userId, string path)
    {
        if (path == "/") return true;

        var trimmed = path.TrimEnd('/');
        int cut = trimmed.LastIndexOf('/');
        var args = new Dictionary<string, string>
        {
            { "@OwnerId", userId.ToString() },
            { "@Path", cut <= 0 ? "/" : trimmed[..cut] },
            { "@Name", trimmed[(cut + 1)..] }
        };
        return DataBaseService.ReadOne<int>(FolderExistsQuery, args) > 0;
    }

    public static int[]? DeleteFolder(int userId, int folderId, string folderFullPath)
    {
        var args = new Dictionary<string, string> { { "@OwnerId", userId.ToString() }, { "@Path", folderFullPath } };
        var fileIds = DataBaseService.ReadMany(SubtreeFileIdsQuery, args, r => r.GetInt32(0)).ToArray();

        bool ok = RunInTransaction(() =>
        {
            DataBaseService.Execute(DeleteSubtreeQuery, args); // FileKeys go with ON DELETE CASCADE
            DataBaseService.Execute(DeleteFileQuery, new Dictionary<string, string> { { "@Id", folderId.ToString() }, { "@OwnerId", userId.ToString() } });
        });
        return ok ? fileIds : null;
    }

    public static bool MoveFolder(int userId, FileInfo updatedFolder, string oldFullPath, string newFullPath)
    {
        var args = new Dictionary<string, string> { { "@OwnerId", userId.ToString() }, { "@Path", oldFullPath }, { "@NewPath", newFullPath } };
        var folderArgs = BuildFileArgs(userId, updatedFolder);
        folderArgs.Add("@Id", updatedFolder.Id.ToString());

        return RunInTransaction(() =>
        {
            DataBaseService.Execute(MoveSubtreeQuery, args);
            DataBaseService.Execute(UpdateFileQuery, folderArgs);
        });
    }


    public static void CreateTables()
    {
        var noArgs = new Dictionary<string, string>();
        DataBaseService.Execute(CreateFileInfoTableQuery, noArgs);
        DataBaseService.Execute(CreateFileKeysTableQuery, noArgs);
        DataBaseService.Execute(CreateFileKeysIndexQuery, noArgs);
        DataBaseService.Execute(CreateFileInfoOwnerIndexQuery, noArgs);
    }


    public static int CreateFileInfo(int userId, FileInfo fileInfo)
    {
        var args = BuildFileArgs(userId, fileInfo);
        int fileId = -1;

        bool ok = RunInTransaction(() =>
        {
            DataBaseService.Execute(CreateFileQuery, args);
            fileId = DataBaseService.ReadOne<int>(LastInsertIdQuery, []);
            ReplacePrivateKeys(fileId, fileInfo.PrivateKeys);
        });

        return ok ? fileId : -1;
    }


    public static FileInfo? GetFileById(int userId, int fileId)
    {
        var args = new Dictionary<string, string>
        {
            { "@Id", fileId.ToString() },
            { "@OwnerId", userId.ToString() }
        };

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

    public static bool DeleteFileInfo(int userId, int fileId)
    {
        if (GetFileById(userId, fileId) is null)
        {
            return false;
        }

        var args = new Dictionary<string, string>
        {
            { "@Id", fileId.ToString() },
            { "@OwnerId", userId.ToString() }
        };
        var keyArgs = new Dictionary<string, string> { { "@FileId", fileId.ToString() } };

        return RunInTransaction(() =>
        {
            // ON DELETE CASCADE ya lo cubre, pero se borra explicitamente por si foreign_keys esta desactivado
            DataBaseService.Execute(DeleteKeysQuery, keyArgs);
            DataBaseService.Execute(DeleteFileQuery, args);
        });
    }

    public static bool UpdateFileInfo(int userId, FileInfo fileInfo)
    {
        // Sin esta comprobacion se podrian reemplazar las claves de un archivo ajeno
        if (GetFileById(userId, fileInfo.Id) is null)
        {
            return false;
        }

        var args = BuildFileArgs(userId, fileInfo);
        args.Add("@Id", fileInfo.Id.ToString());

        return RunInTransaction(() =>
        {
            DataBaseService.Execute(UpdateFileQuery, args);
            ReplacePrivateKeys(fileInfo.Id, fileInfo.PrivateKeys);
        });
    }

    public static int GetFileInfoByNamePath(int userId, string name, string path)
    {
        var query = "SELECT Id FROM FileInfo WHERE OwnerId = @OwnerId AND Name = @Name AND Path = @Path";
        var args = new Dictionary<string, string>
        {
            { "@OwnerId", userId.ToString() },
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

    private static Dictionary<string, string> BuildFileArgs(int userId, FileInfo fileInfo)
    {
        return new Dictionary<string, string>
        {
            { "@OwnerId", userId.ToString() },
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
