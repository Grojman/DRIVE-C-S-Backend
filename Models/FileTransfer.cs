public record UserFileKey(int UserId, string Key);
public record FileTransfer(int Id, UsuarioHeader[] UsersData, string FileData, UserFileKey[] Keys);