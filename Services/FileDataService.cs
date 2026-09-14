public static class FileDataService
{
    private const string ReadFileQuery = "SELECT * FROM FileInfo WHERE Id = @Id";
    private const string DeleteFileQuery = "DELETE FROM FileInfo WHERE Id = @Id";
    private const string UpdateFileQuery = "UPDATE FileInfo SET Name = @Name, Path = @Path, Size = @Size, CreatedAt = @CreatedAt, ModifiedAt = @ModifiedAt, FileType = @FileType, PublicKey = @PublicKey, PrivateKey = @PrivateKey WHERE Id = @Id";
    private const string CreateFileQuery = "INSERT INTO FileInfo (Name, Path, Size, CreatedAt, ModifiedAt, FileType, PublicKey, PrivateKey) VALUES (@Name, @Path, @Size, @CreatedAt, @ModifiedAt, @FileType, @PublicKey, @PrivateKey)";
    public static IEnumerable<FileInfo> GetFilesInDirectory(int directoryId)
    {
        FileInfo directory = DataBaseService.ReadOne<FileInfo>(ReadFileQuery,
            new Dictionary<string, string>()
            {
                { "@Id", directoryId.ToString() }
            }
        );

        if (directory == null || directory.FileType != FileType.Directory)
        {
            return Array.Empty<FileInfo>();
        }

        string[] files = FileSystemService.GetFilesAndDirectories(directory.Path);
        
        List<FileInfo> fileInfos = new List<FileInfo>();
        foreach (var file in files)
        {
            FileInfo fileInfo = DataBaseService.ReadOne<FileInfo>(ReadFileQuery,
                new Dictionary<string, string>()
                {
                    { "@Id", file.ToString() }
                }
            );

            if (fileInfo != null)
            {
                fileInfos.Add(fileInfo);
            }
        }
        return fileInfos;
    }

    public static FileInfo GetFileById(int fileId)
    {
        return DataBaseService.ReadOne<FileInfo>(ReadFileQuery,
            new Dictionary<string, string>()
            {
                { "@Id", fileId.ToString() }
            }
        );
    }

    public static bool DeleteFileInfo(int fileId)
    {
        var args = new Dictionary<string, string> { { "@Id", fileId.ToString() } };
        try
        {
            DataBaseService.Execute(DeleteFileQuery, args);
            return true;
        }
        catch (Exception)
        {
            return false;
        }
    }

    public static bool UpdateFileInfo(FileInfo fileInfo)
    {
        var args = new Dictionary<string, string>
        {
            { "@Id", fileInfo.Id.ToString() },
            { "@Name", fileInfo.Name },
            { "@Path", fileInfo.Path },
            { "@Size", fileInfo.Size.ToString() },
            { "@CreatedAt", fileInfo.CreatedAt.ToString("yyyy-MM-dd HH:mm:ss") },
            { "@ModifiedAt", fileInfo.ModifiedAt.ToString("yyyy-MM-dd HH:mm:ss") },
            { "@FileType", fileInfo.FileType.ToString() },
            { "@PublicKey", fileInfo.PublicKey },
            { "@PrivateKey", fileInfo.PrivateKey }
        };

        try
        {
            DataBaseService.Execute(UpdateFileQuery, args);
            return true;
        }
        catch (Exception)
        {
            return false;
        }
    }

    public static bool CreateFileInfo(FileInfo fileInfo)
    {
        var args = new Dictionary<string, string>
        {
            { "@Name", fileInfo.Name },
            { "@Path", fileInfo.Path },
            { "@Size", fileInfo.Size.ToString() },
            { "@CreatedAt", fileInfo.CreatedAt.ToString("yyyy-MM-dd HH:mm:ss") },
            { "@ModifiedAt", fileInfo.ModifiedAt.ToString("yyyy-MM-dd HH:mm:ss") },
            { "@FileType", fileInfo.FileType.ToString() },
            { "@PublicKey", fileInfo.PublicKey },
            { "@PrivateKey", fileInfo.PrivateKey }
        };

        try
        {
            DataBaseService.Execute(CreateFileQuery, args);
            return true;
        }
        catch (Exception)
        {
            return false;
        }
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
}