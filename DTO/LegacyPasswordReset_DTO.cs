/// <summary>Proof of the old password and replacement password/key material for an expired legacy account.</summary>
public record LegacyPasswordReset_DTO(
    string user,
    string old_password,
    string new_password,
    string private_key,
    string key_salt,
    string key_kdf);
