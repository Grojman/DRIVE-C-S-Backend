/// <summary>Client-encrypted private-key ciphertext and its key derivation metadata.</summary>
public record PrivateKeyUpdate_DTO(
    string private_key,
    string key_salt,
    string key_kdf);
