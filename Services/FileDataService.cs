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
            UserId INTEGER NOT NULL,
            PrivateKey TEXT NOT NULL,
            FOREIGN KEY (FileId) REFERENCES FileInfo(Id) ON DELETE CASCADE,
            FOREIGN KEY (UserId) REFERENCES Users(Id) ON DELETE CASCADE
        )";
    private const string FileKeysColumnsQuery = "SELECT name FROM pragma_table_info('FileKeys')";
    private const string AddFileKeysUserIdQuery = "ALTER TABLE FileKeys ADD COLUMN UserId INTEGER NOT NULL DEFAULT 0";
    private const string CreateFileKeysUserIndexQuery = "CREATE INDEX IF NOT EXISTS IX_FileKeys_UserId ON FileKeys (UserId)";
    private const string CreateFileKeysIndexQuery = "CREATE INDEX IF NOT EXISTS IX_FileKeys_FileId ON FileKeys (FileId)";
    private const string CreateFileInfoOwnerIndexQuery = "CREATE INDEX IF NOT EXISTS IX_FileInfo_OwnerId ON FileInfo (OwnerId)";

    private const string ReadFileQuery = "SELECT Id, Name, Path, Size, CreatedAt, ModifiedAt, FileType FROM FileInfo WHERE Id = @Id AND OwnerId = @OwnerId";
    private const string DeleteFileQuery = "DELETE FROM FileInfo WHERE Id = @Id AND OwnerId = @OwnerId";
    private const string UpdateFileQuery = "UPDATE FileInfo SET Name = @Name, Path = @Path, Size = @Size, CreatedAt = @CreatedAt, ModifiedAt = @ModifiedAt, FileType = @FileType WHERE Id = @Id AND OwnerId = @OwnerId";
    private const string CreateFileQuery = "INSERT INTO FileInfo (OwnerId, Name, Path, Size, CreatedAt, ModifiedAt, FileType) VALUES (@OwnerId, @Name, @Path, @Size, @CreatedAt, @ModifiedAt, @FileType)";
    private const string LastInsertIdQuery = "SELECT last_insert_rowid()";

    private const string ReadUsersDataQuery = "SELECT u.Id, u.Username, u.PublicKey FROM FileKeys k JOIN Users u ON u.Id = k.UserId WHERE k.FileId = @FileId ORDER BY k.Id";
    private const string ReadUserKeyQuery = "SELECT PrivateKey FROM FileKeys WHERE FileId = @FileId AND UserId = @UserId";
    private const string ReadUserKeysQuery = "SELECT PrivateKey as Key, UserId FROM FileKeys WHERE FileId = @FileId";
    private const string ReadOwnerQuery = "SELECT OwnerId FROM FileInfo WHERE Id = @Id";
    private const string ListSharedQuery = "SELECT f.Id, f.Name, f.Path, f.Size, f.CreatedAt, f.ModifiedAt, f.FileType FROM FileInfo f JOIN FileKeys k ON k.FileId = f.Id WHERE k.UserId = @UserId AND f.OwnerId != @UserId ORDER BY f.Name";
    private const string DeleteKeysQuery = "DELETE FROM FileKeys WHERE FileId = @FileId";
    private const string CreateKeyQuery = "INSERT INTO FileKeys (FileId, UserId, PrivateKey) VALUES (@FileId, @UserId, @PrivateKey)";

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
            .Select(f => f with { UsersData = GetUsersData(f.Id) });
    }

    public static IEnumerable<FileInfo> GetSharedFiles(int userId)
    {
        var args = new Dictionary<string, string> { { "@UserId", userId.ToString() } };
        return DataBaseService.ReadMany(ListSharedQuery, args, MapFileInfo)
            .ToList()
            .Select(f => f with { UsersData = GetUsersData(f.Id) });
    }

    public static int? GetOwnerId(int fileId)
    {
        try
        {
            return DataBaseService.ReadOne<int>(ReadOwnerQuery, new Dictionary<string, string> { { "@Id", fileId.ToString() } });
        }
        catch (InvalidOperationException)
        {
            return null;
        }
    }

    public static string? GetUserKey(int userId, int fileId)
    {
        var args = new Dictionary<string, string> { { "@FileId", fileId.ToString() }, { "@UserId", userId.ToString() } };
        try
        {
            return DataBaseService.ReadOne<string>(ReadUserKeyQuery, args);
        }
        catch (InvalidOperationException)
        {
            return null;
        }
    }
    public static IEnumerable<UserFileKey> GetUserKeys(int fileId)
    {
        var args = new Dictionary<string, string> { { "@FileId", fileId.ToString() } };
        try
        {
            return DataBaseService.ReadMany<UserFileKey>(ReadUserKeysQuery, args);
        }
        catch (InvalidOperationException)
        {
            return [];
        }
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
        if (!DataBaseService.ReadMany<string>(FileKeysColumnsQuery, noArgs).Contains("UserId"))
        {
            DataBaseService.Execute(AddFileKeysUserIdQuery, noArgs);
        }
        DataBaseService.Execute(CreateFileKeysIndexQuery, noArgs);
        DataBaseService.Execute(CreateFileKeysUserIndexQuery, noArgs);
        DataBaseService.Execute(CreateFileInfoOwnerIndexQuery, noArgs);
    }


    public static int CreateFileInfo(int userId, FileInfo fileInfo, UserFileKey[]? keys)
    {
        var args = BuildFileArgs(userId, fileInfo);
        int fileId = -1;

        bool ok = RunInTransaction(() =>
        {
            DataBaseService.Execute(CreateFileQuery, args);
            fileId = DataBaseService.ReadOne<int>(LastInsertIdQuery, []);
            ReplaceKeys(fileId, keys);
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
            return fileInfo with { UsersData = GetUsersData(fileId) };
        }
        catch (InvalidOperationException)
        {
            return null;
        }
    }

    public static UsuarioHeader[] GetUsersData(int fileId)
    {
        var args = new Dictionary<string, string> { { "@FileId", fileId.ToString() } };
        return DataBaseService.ReadMany(ReadUsersDataQuery, args, reader => new UsuarioHeader(reader.GetInt32(0), reader.GetString(1), reader.GetString(2))).ToArray();
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

    public static bool UpdateFileInfo(int userId, FileInfo fileInfo, UserFileKey[]? keys = null)
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
            if (keys is not null) ReplaceKeys(fileInfo.Id, keys);
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

    private static void ReplaceKeys(int fileId, UserFileKey[]? keys)
    {
        DataBaseService.Execute(DeleteKeysQuery, new Dictionary<string, string> { { "@FileId", fileId.ToString() } });

        foreach (var key in keys ?? Array.Empty<UserFileKey>())
        {
            DataBaseService.Execute(CreateKeyQuery, new Dictionary<string, string>
            {
                { "@FileId", fileId.ToString() },
                { "@UserId", key.UserId.ToString() },
                { "@PrivateKey", key.Key }
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
            Array.Empty<UsuarioHeader>(),
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
