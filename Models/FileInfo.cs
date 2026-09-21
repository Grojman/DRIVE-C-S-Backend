public record FileInfo(int Id, string Name, string Path, long Size, string PublicKey, string[] PrivateKeys, DateTime CreatedAt, DateTime ModifiedAt, FileType FileType);
public enum FileType
{
    File,
    Directory
}