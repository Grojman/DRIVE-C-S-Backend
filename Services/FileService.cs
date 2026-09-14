using System.Reflection.Metadata.Ecma335;
using Microsoft.AspNetCore.Razor.TagHelpers;

public static class FileService
{
    public static bool CreateFile(FileInfo info, string fileData)
    {
        if(FileDataService.CreateFileInfo(info))
        {
            int id = FileDataService.GetFileInfoByNamePath(info.Name, info.Path);
            var route = Path.Combine(info.Path,  id.ToString());

            return info.FileType == FileType.Directory ? FileSystemService.CreateDirectory(route) : FileSystemService.CreateFile(route, fileData);
        }
        return false;
    }

    public static FileTransfer? GetFile(int Id)
    {
        var data = FileDataService.GetFileById(Id);

        if(data is not null)
        {
            var fileData = FileSystemService.ReadFileContent(Path.Combine(data.Path, Id.ToString()));
            return new(Id, data.PrivateKey, fileData);
        }

        return null;
    }

    public static bool UpdateFile(FileInfo info, string fileData)
    {
        if(FileDataService.UpdateFileInfo(info))
        {
            return info.FileType == FileType.Directory || FileSystemService.ReWriteFile(Path.Combine(info.Path, info.Id.ToString()), fileData);
        }
        return false;
    }

    public static bool DeleteFile(int Id)
    {
        var data = FileDataService.GetFileById(Id);

        if(data is not null)
        {
            string path = Path.Combine(data.Path, data.Id.ToString());
            bool deleted = data.FileType == FileType.File ? FileSystemService.RemoveFile(path) : FileSystemService.RemoveDirectory(path);

            if(deleted)
            {
                return FileDataService.DeleteFileInfo(data.Id);
            }
        }
        return false;
    }
}