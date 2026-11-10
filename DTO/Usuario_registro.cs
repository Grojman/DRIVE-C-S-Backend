/// <summary>Account credentials and client-encrypted key material used during registration.</summary>
public record Usuario_registro_DTO(
    string user,
    string password,
    string public_key,
    string private_key,
    string key_salt,
    string key_kdf);