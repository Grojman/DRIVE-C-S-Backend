public static class FileService
{
    private static string FileRoute(int userId, int fileId) => Path.Combine(userId.ToString(), fileId.ToString());

    public static string FullPath(FileInfo folder) => folder.Path == "/" ? "/" + folder.Name : folder.Path.TrimEnd('/') + "/" + folder.Name;
    public static bool CreateFile(int userId, FileInfo info, string fileData)
{
        if (!FileDataService.FolderExists(userId, info.Path) || FileDataService.GetFileInfoByNamePath(userId, info.Name, info.Path) != -1)
        {
            return false;
        }

        int id = FileDataService.CreateFileInfo(userId, info);
        if (id == -1) return false;
        if (info.FileType == FileType.Directory) return true;

        FileSystemService.CreateDirectory(userId.ToString());
        if (FileSystemService.CreateFile(FileRoute(userId, id), fileData)) return true;

        FileDataService.DeleteFileInfo(userId, id);
        return false;
    }

    public static FileTransfer? GetFile(int userId, int Id)
    {
        try
        {
            
        var data = FileDataService.GetFileById(userId, Id);

        if(data is not null && data.FileType == FileType.File)
        {
            var route = UserRoute(userId, data.Path, Id.ToString());
            if(route is null)
            {
                return null;
            }

            var fileData = FileSystemService.ReadFileContent(route);
            return new(Id, data.PrivateKeys, fileData);
        }
        } catch (FileNotFoundException)
        {
            return null;
        }

        return null;
    }

    public static bool UpdateFile(int userId, FileInfo info, string fileData)
    {
        var route = UserRoute(userId, info.Path, info.Id.ToString());
        if(route is null)
        {
            return false;
        }

        if(FileDataService.UpdateFileInfo(userId, info))
        {
            return info.FileType == FileType.Directory || FileSystemService.ReWriteFile(route, fileData);
        }
        return false;
    }

    public static bool DeleteFile(int userId, int Id)
    {
        var data = FileDataService.GetFileById(userId, Id);

        if(data is not null)
        {
            string? path = UserRoute(userId, data.Path, data.Id.ToString());
            if(path is null)
            {
                return false;
            }

            bool deleted = data.FileType == FileType.File ? FileSystemService.RemoveFile(path) : FileSystemService.RemoveDirectory(path);

            if(deleted)
            {
                return FileDataService.DeleteFileInfo(userId, data.Id);
            }
        }
        return false;
    }

    // Devuelve la ruta relativa dentro de la carpeta del usuario, o null si la ruta intenta salir de ella (../, rutas absolutas)
    private static string? UserRoute(int userId, params string[] parts)
    {
        string userRoot = Path.GetFullPath(userId.ToString());
        string route = Path.Combine([userId.ToString(), .. parts.Select(p => p.TrimStart('/', '\\'))]);
        string fullRoute = Path.GetFullPath(route);

        bool insideUserRoot = fullRoute == userRoot || fullRoute.StartsWith(userRoot + Path.DirectorySeparatorChar);
        return insideUserRoot ? route : null;
    }
}
