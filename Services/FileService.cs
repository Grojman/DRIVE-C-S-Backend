public static class FileService
{
    private static string FileRoute(int userId, int fileId) => UploadService.FileRoute(userId, fileId);

    public static string FullPath(FileInfo folder) => folder.Path == "/" ? "/" + folder.Name : folder.Path.TrimEnd('/') + "/" + folder.Name;

    // Solo carpetas: el contenido de los archivos se crea mediante UploadService
    public static bool CreateFolder(int userId, FileInfo info)
    {
        if (info.FileType != FileType.Directory ||
            !FileDataService.FolderExists(userId, info.Path) ||
            FileDataService.GetFileInfoByNamePath(userId, info.Name, info.Path) != -1)
        {
            return false;
        }

        return FileDataService.CreateFileInfo(userId, info, null) != -1;
    }

    // Lo necesario para descargar: la clave del usuario y cómo está guardado el contenido.
    // Los archivos antiguos (formato 1) traen el contenido en FileData; los nuevos se piden trozo a trozo
    public static FileManifest? GetFile(int userId, int Id)
    {
        try
        {
            var userKey = FileDataService.GetUserKey(userId, Id);
            var storage = FileDataService.GetStorageInfo(Id);
            if (userKey is null || storage is null || storage.FileType != FileType.File || storage.Status != "Ready")
            {
                return null;
            }

            var usersData = FileDataService.GetUsersData(Id);
            var keys = new[] { new UserFileKey(userId, userKey) };

            if (storage.Format == FileDataService.LegacyFormat)
            {
                var fileData = FileSystemService.ReadFileContent(FileRoute(storage.OwnerId, Id));
                return new(Id, usersData, keys, storage.Format, 1, 0, storage.Size, 0, fileData);
            }

            return new(Id, usersData, keys, storage.Format, storage.ChunkCount, storage.ChunkSize, storage.Size, storage.ContentId, null);
        }
        catch (FileNotFoundException)
        {
            return null;
        }
    }

    // Ruta absoluta de un trozo, o null si el usuario no tiene acceso o el trozo no existe
    public static string? GetChunkPath(int userId, int fileId, int index)
    {
        var storage = FileDataService.GetStorageInfo(fileId);
        if (storage is null || storage.Format != FileDataService.ChunkedFormat || storage.Status != "Ready" ||
            index < 0 || index >= storage.ChunkCount || FileDataService.GetUserKey(userId, fileId) is null)
        {
            return null;
        }

        var path = FileSystemService.FullPath(UploadService.StoredChunkRoute(storage.OwnerId, fileId, index));
        return File.Exists(path) ? path : null;
    }

    public static bool UpdateFolder(int userId, FileInfo info)
    {
        return info.FileType == FileType.Directory && FileDataService.UpdateFileInfo(userId, info);
    }

    public static bool DeleteFile(int userId, int Id)
    {
        var data = FileDataService.GetFileById(userId, Id);
        if (data is null)
        {
            return false;
        }

        if (data.FileType == FileType.File)
        {
            UploadService.DiscardForFile(Id);
            // Formato 1 = un archivo, formato 2 = un directorio con los trozos: RemoveEntry borra cualquiera de los dos
            FileSystemService.RemoveEntry(FileRoute(userId, Id));
        }
        return FileDataService.DeleteFileInfo(userId, data.Id);
    }
}

// Respuesta de GET /file. Para el formato 2 FileData es null y el contenido se descarga con GET /file/chunk
public record FileManifest(
    int Id,
    UsuarioHeader[] UsersData,
    UserFileKey[] Keys,
    int Format,
    int ChunkCount,
    int ChunkSize,
    long Size,
    int ContentId,
    string? FileData);
