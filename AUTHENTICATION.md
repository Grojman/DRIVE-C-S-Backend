# Authentication and key protection

## Password storage and pepper

The backend hashes registration passwords with Argon2id (64 MiB, 3 iterations, parallelism 1) and a fresh 16-byte salt per account. The database stores a self-describing Argon2id hash. Before Argon2id, the backend applies HMAC-SHA-256 using the server-only pepper.

Do not put the pepper in frontend configuration or commit it to the repository. For local development, set it in ASP.NET Core User Secrets:

```powershell
$rng = [Security.Cryptography.RandomNumberGenerator]::Create()
$bytes = New-Object byte[] 32
$rng.GetBytes($bytes)
$pepper = [Convert]::ToBase64String($bytes)
dotnet user-secrets set "Authentication:Pepper" $pepper --project .\DRIVE-C-S-Backend.csproj
[Array]::Clear($bytes, 0, $bytes.Length)
$rng.Dispose()
Remove-Variable pepper, bytes, rng
```

In deployed environments, provide `Authentication__Pepper` via the platform's secret manager/environment injection. The backend intentionally refuses to start if the setting is absent or invalid. Keep the same pepper while hashes depend on it; rotating it requires a planned password re-verification/reset.

## Existing accounts

On first startup with the updated backend, a database setting records the start of a **90-day** legacy migration period. Existing password records are marked as legacy by the schema migration. A successful login during that period upgrades the verifier to Argon2id.

At the end of the period, a legacy login with the existing password returns a reset-required response. The user must then provide a new password; the client decrypts the private key with the old password, re-encrypts it using Argon2id and the new password, and submits both passwords and the new ciphertext to `/password/reset`. This endpoint cannot recover an account when its old password is forgotten: the project has no verified email or recovery key. Because the server cannot decrypt users' private keys, a password reset without the old password would make existing encrypted files inaccessible.

Update the frontend and backend together. Login/register/reset requests now contain the password itself. The API rejects cleartext authentication from non-loopback clients, and the frontend also blocks non-HTTPS authentication outside local development. Serve the application and API over HTTPS in production; if TLS terminates at a reverse proxy, configure trusted forwarded-protocol handling so ASP.NET Core can identify the original HTTPS request. The frontend defaults to the same-origin API when deployed; configure a same-origin reverse proxy to the backend.

## Private-key encryption

The browser derives a separate AES-128 key with Argon2id and a fresh random 16-byte salt. The encrypted private key, salt, and KDF version/parameters are stored by the backend. The backend pepper is not involved in this derivation and is never sent to the browser.

The backend automatically adds the new account/key metadata columns to an existing SQLite database. Back up the database before deploying this migration.
