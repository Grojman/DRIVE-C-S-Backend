public record FileInfo(int Id, string Name, string Path, long Size, UsuarioHeader[] UsersData, DateTime CreatedAt, DateTime ModifiedAt, FileType FileType);
public enum FileType
{
    File,
    Directory
}