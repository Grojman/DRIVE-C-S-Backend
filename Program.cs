
using System.Collections;
using System.Text.Json.Serialization;

internal class Program
{   

    /// <summary>Authenticated user data and tokens returned after login or registration.</summary>
    public record LoggedInUser(
        int Id,
        string Name,
        string AccessToken,
        string RefreshToken,
        string PrivateKey,
        string PublicKey,
        string? KeySalt,
        string? KeyKdf);

    /// <summary>Response asking a legacy account to reset its password after the migration deadline.</summary>
    public record LegacyPasswordResetRequired(string Code, string PrivateKey);

    private static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);
        JwtService.Configure(builder.Configuration);
        var passwordHasher = new Argon2IDService(builder.Configuration);
        DataBaseService.Start();
        FileSystemService.Start();
        builder.WebHost.ConfigureKestrel(options =>
        {
            options.Limits.MaxRequestBodySize = null; // tamaño de envío ilimitado
        });

        builder.Services.AddCors( o => o.AddDefaultPolicy(p =>
        p.WithOrigins("http://localhost:4200")
        .AllowAnyHeader()
        .AllowAnyMethod()));

        builder.Services.ConfigureHttpJsonOptions(o =>
        {
            o.SerializerOptions.PropertyNamingPolicy = null; // se mantiene siempre en pascalCase
            o.SerializerOptions.Converters.Add(new JsonStringEnumConverter()); //evita que los enums se parseen como enteros
        });
        builder.Services.AddOpenApi();

        var app = builder.Build();

        app.UseCors();

        app.UseMiddleware<AuthMiddleware>();

        if (app.Environment.IsDevelopment())
        {
            app.MapOpenApi();
        }

        app.MapGet("/", () => "Hello World!");

        var securedGroup = app.MapGroup("").RequireSession();

        //- "/login": POST: username, password
        app.MapPost("/login", async(HttpContext request) =>
        {
            if (!IsSecureAuthenticationRequest(request))
            {
                return Results.StatusCode(StatusCodes.Status426UpgradeRequired);
            }

            var person = await request.Request.ReadBase64JsonAsync<Usuario_login_DTO>();
            if (person is null ||
                string.IsNullOrWhiteSpace(person.user) ||
                string.IsNullOrEmpty(person.password) ||
                person.password.Length > 1024)
            {
                return Results.BadRequest();
            }

            var user = UserService.GetUser(person.user);
            if (user is null)
            {
                return Results.Unauthorized();
            }

            if (user.PasswordScheme == "argon2id")
            {
                if (!await passwordHasher.VerifyPasswordAsync(person.password, user.Password))
                {
                    return Results.Unauthorized();
                }
            }
            else if (user.PasswordScheme == "legacy")
            {
                if (!UserService.IsLegacyPasswordValid(user, person.password))
                {
                    return Results.Unauthorized();
                }

                if (!UserService.IsLegacyMigrationOpen())
                {
                    return Results.Json(
                        new LegacyPasswordResetRequired("LegacyPasswordResetRequired", user.PrivateKey),
                        statusCode: StatusCodes.Status428PreconditionRequired);
                }

                var upgradedHash = await passwordHasher.HashPasswordAsync(person.password);
                if (!UserService.UpgradeLegacyPassword(user.Username, user.Password, upgradedHash))
                {
                    user = UserService.GetUser(person.user);
                    if (user is null ||
                        user.PasswordScheme != "argon2id" ||
                        !await passwordHasher.VerifyPasswordAsync(person.password, user.Password))
                    {
                        return Results.Unauthorized();
                    }
                }
            }
            else
            {
                return Results.Unauthorized();
            }

            user = UserService.GetUser(person.user);
            if (user is null)
            {
                return Results.Unauthorized();
            }

            var tokens = JwtService.IssueTokens(user.Id);
            return Results.Ok(ToLoggedInUser(user, tokens));
        })
            .WithName("Login")
            .WithSummary("Authenticate and migrate an existing password when needed")
            .WithDescription("Accepts the raw password over HTTPS. Legacy accounts are migrated during the 90-day window; after it, a reset is required.")
            .Produces<LoggedInUser>(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces<LegacyPasswordResetRequired>(StatusCodes.Status428PreconditionRequired)
            .Produces(StatusCodes.Status426UpgradeRequired);

        //- "/signin": POST: username, password, encrypted private/public keys, key derivation metadata
        app.MapPost("/signin", async(HttpContext request) =>
        {
            if (!IsSecureAuthenticationRequest(request))
            {
                return Results.StatusCode(StatusCodes.Status426UpgradeRequired);
            }

            var person = await request.Request.ReadBase64JsonAsync<Usuario_registro_DTO>();
            if (person is null ||
                string.IsNullOrWhiteSpace(person.user) ||
                string.IsNullOrEmpty(person.password) ||
                person.password.Length is < 8 or > 1024 ||
                string.IsNullOrEmpty(person.private_key) ||
                string.IsNullOrEmpty(person.public_key) ||
                !IsValidKeyMetadata(person.key_salt, person.key_kdf))
            {
                return Results.BadRequest();
            }

            if (UserService.IsUsernameTaken(person.user))
            {
                return Results.Conflict();
            }

            var passwordHash = await passwordHasher.HashPasswordAsync(person.password);
            try
            {
                UserService.CreateUser(
                    person.user,
                    passwordHash,
                    person.private_key,
                    person.public_key,
                    person.key_salt,
                    person.key_kdf);
            }
            catch (Microsoft.Data.Sqlite.SqliteException)
            {
                return Results.Conflict();
            }

            var user = UserService.GetUser(person.user);
            if (user is null)
            {
                return Results.Conflict();
            }

            var tokens = JwtService.IssueTokens(user.Id);
            return Results.Ok(ToLoggedInUser(user, tokens));
        })
            .WithName("Register")
            .WithSummary("Create an account using Argon2id")
            .WithDescription("The client encrypts the private key first; the backend stores only its ciphertext and KDF metadata.")
            .Produces<LoggedInUser>(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status409Conflict)
            .Produces(StatusCodes.Status426UpgradeRequired);

        app.MapPost("/password/reset", async(HttpContext request) =>
        {
            if (!IsSecureAuthenticationRequest(request))
            {
                return Results.StatusCode(StatusCodes.Status426UpgradeRequired);
            }

            var data = await request.Request.ReadBase64JsonAsync<LegacyPasswordReset_DTO>();
            if (data is null ||
                string.IsNullOrWhiteSpace(data.user) ||
            string.IsNullOrEmpty(data.old_password) ||
            data.old_password.Length > 1024 ||
            string.IsNullOrEmpty(data.new_password) ||
            data.new_password.Length is < 8 or > 1024 ||
            string.IsNullOrEmpty(data.private_key) ||
            !IsValidKeyMetadata(data.key_salt, data.key_kdf))
            {
                return Results.BadRequest();
            }

            if (UserService.IsLegacyMigrationOpen())
            {
                return Results.Conflict();
            }

            var user = UserService.GetUser(data.user);
            if (user is null || !UserService.IsLegacyPasswordValid(user, data.old_password))
            {
                return Results.Unauthorized();
            }

            var passwordHash = await passwordHasher.HashPasswordAsync(data.new_password);
            if (!UserService.ResetLegacyPassword(
                data.user,
                user.Password,
                passwordHash,
                data.private_key,
                data.key_salt,
                data.key_kdf))
            {
                return Results.Conflict();
            }

            user = UserService.GetUser(data.user);
            if (user is null)
            {
                return Results.Conflict();
            }

            var tokens = JwtService.IssueTokens(user.Id);
            return Results.Ok(ToLoggedInUser(user, tokens));
        })
            .WithName("ResetLegacyPassword")
            .WithSummary("Reset a legacy password after the migration window")
            .WithDescription("Requires the old password and a new password. The client must re-encrypt the private key with the new password.")
            .Produces<LoggedInUser>(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status409Conflict)
            .Produces(StatusCodes.Status426UpgradeRequired);

        //  "/username/{username}": GET: Usuario 
        app.MapGet("/username/{username}", async(string username) =>
        {
            return Results.Ok(UserService.IsUsernameTaken(username));
        });

        securedGroup.MapPut("/user/private-key", async(HttpContext request) =>
        {
            var data = await request.Request.ReadBase64JsonAsync<PrivateKeyUpdate_DTO>();
            if (data is null ||
                string.IsNullOrEmpty(data.private_key) ||
                !IsValidKeyMetadata(data.key_salt, data.key_kdf))
            {
                return Results.BadRequest();
            }

            return UserService.UpdatePrivateKey(
                request.GetUserId(),
                data.private_key,
                data.key_salt,
                data.key_kdf)
                ? Results.Ok(true)
                : Results.Conflict();
        })
            .WithName("UpdatePrivateKey")
            .WithSummary("Store a migrated encrypted private key")
            .WithDescription("Requires a valid session and stores only ciphertext, salt, and KDF metadata.")
            .Produces<bool>(StatusCodes.Status200OK)
            .Produces(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status409Conflict);

        securedGroup.MapGet("/users", async(HttpContext request) =>
        {
            var userId = request.GetUserId();

            return UserService.GetUsers(userId).Select(n => new UsuarioHeader(n.Id, n.Username, n.PublicKey));
        });

        //  "/logout": POST: userId
        securedGroup.MapPost("/logout", async(HttpContext request) =>
        {
            var data = await request.Request.ReadBase64JsonAsync<RefreshTokenDTO>();
            if (data is null || string.IsNullOrEmpty(data.RefreshToken)) return Results.BadRequest("Error at logging out.");

            // El token de acceso sigue siendo válido hasta que caduque; lo que se invalida es el de refresco
            JwtService.RevokeRefreshToken(data.RefreshToken);
            return Results.Ok("Succesfully logged out");
        });

        //  "/refresh": POST: token de refresco -> nuevo par de tokens (el anterior deja de valer)
        app.MapPost("/refresh", async(HttpContext request) =>
        {
            var data = await request.Request.ReadBase64JsonAsync<RefreshTokenDTO>();
            if (data is null || string.IsNullOrEmpty(data.RefreshToken)) return Results.BadRequest();

            var tokens = JwtService.Refresh(data.RefreshToken);
            return tokens is null ? Results.Unauthorized() : Results.Ok(tokens);
        });

        //  - "/files" GET: userId, Ruta (SOLO METADATOS)[Vector]
        var listLocal = async(HttpContext request, string targetDirectory) =>
        {
            targetDirectory = targetDirectory.Decode();
            var userId = request.GetUserId();
            IEnumerable files = FileDataService.GetFilesInPath(userId, targetDirectory);
            return files;
        };
        securedGroup.MapGet("/files", listLocal);
        securedGroup.MapGet("/files/local", listLocal);

        //  - "/files/shared" GET: userId (archivos de otros usuarios que tienen una clave para este usuario)
        securedGroup.MapGet("/files/shared", async(HttpContext request) =>
        {
            return FileDataService.GetSharedFiles(request.GetUserId());
        });

        securedGroup.MapGet("/file/key", async(HttpContext request) =>
        {
           var userId = request.GetUserId();
           var fileId = request.Request.Query["FileId"].ToString();
           if (int.TryParse(request.Request.ReadBase64Query("FileId"), out int id))
            {
                var key = FileDataService.GetUserKey(userId, id);
                if (key is not null)
                {
                    return Results.Ok(key);
                }
            }
            return Results.NotFound("File not found");    

        });

        securedGroup.MapGet("/file/keys", async(HttpContext request) =>
        {
            var userId = request.GetUserId();
            var fileId = request.Request.Query["FileId"].ToString();
            if (int.TryParse(request.Request.ReadBase64Query("FileId"), out int id))
            {
                var keys = FileDataService.GetUserKeys(id);
                if (keys is not null)
                {
                    return Results.Ok(keys);
                }
            }
            return Results.NotFound("File not found");
        });

        // TODO: THE SERVICE SHOULD GET THE TRUE USER ID IN ORDER TO CREATE FILES UNDER IT

        //  - "/file" GET: userId, Ruta (EL ARCHIVO)
        securedGroup.MapGet("/file", async(HttpContext request) =>
        {
            var userId = request.GetUserId();
            var fileId = request.Request.Query["FileId"].ToString();

            
            if (int.TryParse(request.Request.ReadBase64Query("FileId"), out int id))
            {
                
                var file = FileService.GetFile(userId, id);

                if (file is not null)
                {
                    return Results.Ok(file);
                }
            }
            return Results.NotFound("File not found");
        });

        securedGroup.MapPost("/file", async(HttpContext request) =>
        {
            var userId = request.GetUserId();
            var info = await request.Request.ReadBase64JsonAsync<NewFileDTO>();
            if (info is not null)
            {
                var folderInfo = new FileInfo(-1, info.FileName, info.FilePath, info.Size, info.data.UsersData ?? [], DateTime.Now, DateTime.Now, FileType.File);
                if (FileService.CreateFile(userId, folderInfo, info.data.FileData, info.data.Keys))
                {
                    return Results.Ok("File created successfully");
                }
            }
            return Results.BadRequest("Error creating file");
        });

        securedGroup.MapPut("/file", async(HttpContext request) =>
        {
            var userId = request.GetUserId();
            var transferInfo = await request.Request.ReadBase64JsonAsync<NewFileDTO>();

            if(transferInfo is not null)
            {
                var fileInfo = FileDataService.GetFileById(userId, transferInfo.data.Id);
                if(fileInfo is not null)
                {
                    var newinfo = fileInfo with { 
                        Name = transferInfo.FileName,
                        Path = transferInfo.FilePath,
                        Size = transferInfo.Size,
                        ModifiedAt = DateTime.Now};
                    if (FileService.UpdateFile(userId,newinfo, transferInfo.data.FileData))
                    {
                        return Results.Ok("File updated successfully");
                    }
                }
            }
            return Results.BadRequest("Error updating file");
        });

        securedGroup.MapPut("/file/data", async(HttpContext request) => {
            var userId = request.GetUserId();
            var data = await request.Request.ReadBase64JsonAsync<UpdateFileInfoDTO>();

            if (data is null) return Results.BadRequest();

            var currentFiledata = FileDataService.GetFileById(userId, data.FileId);

            if (currentFiledata is null) return Results.NotFound();

            if (data.FileName is not null && 
               (data.FileName.Length == 0 || data.FileName.Contains('/') || data.FileName.Contains("..")))
                return Results.BadRequest("Invalid file name");

            if (data.Keys is not null && data.Keys.Length == 0) return Results.BadRequest("At least one key is required");

            var updated = currentFiledata with
            {
                Name = data.FileName ?? currentFiledata.Name,
                Path = data.FilePath ?? currentFiledata.Path,
                ModifiedAt = DateTime.Now
            };

            bool renamedOrMoved = updated.Name != currentFiledata.Name || updated.Path != currentFiledata.Path;
            if (renamedOrMoved)
            {
                if (!FileDataService.FolderExists(userId, updated.Path)) return Results.BadRequest("Destination folder not found");
                if (FileDataService.GetFileInfoByNamePath(userId, updated.Name, updated.Path) != -1) return Results.BadRequest("A file with that name already exists");
            }

            var result = updated.FileType == FileType.File ?
                         FileDataService.UpdateFileInfo(userId, updated, data.Keys) :
                         FileDataService.MoveFolder(userId, updated, currentFiledata.Path, updated.Path);

            return result ? Results.Ok(true) : Results.BadRequest("Error updating file info");
        });

        securedGroup.MapDelete("/file", async(HttpContext request) =>
        {
            var data = await request.Request.ReadBase64JsonAsync<DeleteFileDTO>();
            if (data is null) return Results.BadRequest();
            return FileService.DeleteFile(request.GetUserId(), data.FileId) ? Results.Ok(true) : Results.NotFound();
        });

        securedGroup.MapPost("/folder", async(HttpContext request) =>
        {
            var userId = request.GetUserId();

            var info = await request.Request.ReadBase64JsonAsync<FolderInfoDTO>();
            if (info is not null)
            {
                var folderInfo = new FileInfo(-1, info.FolderName, info.FolderPath, 0, [], DateTime.Now, DateTime.Now, FileType.Directory);
                if (FileService.CreateFile(userId, folderInfo, string.Empty))
                {
                    return Results.Ok("Folder created successfully");
                }
            }
            return Results.BadRequest("Error creating folder");
        });

        securedGroup.MapDelete("/folder", async(HttpContext request) =>
        {
            var userId = request.GetUserId();
            var data = await request.Request.ReadBase64JsonAsync<DeleteFolderInfoDTO>();

            if (data is not null)
            {
                if (FileService.DeleteFile(userId, data.FolderId))
                {
                    return Results.Ok("Folder deleted successfully");
                }
            }
            return Results.NotFound("Folder not found or could not be deleted");
        });

        securedGroup.MapPut("/folder", async(HttpContext request) =>
        {
            var userId = request.GetUserId();
            var data = await request.Request.ReadBase64JsonAsync<RenameFolderInfoDTO>();

            if (data is not null)
            {
                var currentInfo = FileDataService.GetFileById(userId, data.FolderId);
                if (currentInfo is not null)
                {
                    var updatedInfo = currentInfo with { Name = data.NewName };
                    if (FileService.UpdateFile(userId, updatedInfo, string.Empty))
                    {
                        return Results.Ok("Folder renamed successfully");
                    }
                }

            }
            return Results.BadRequest("Error updating folder");
        });

        app.Run();
    }

    private static LoggedInUser ToLoggedInUser(UserService.UserDB user, AuthTokens tokens) =>
        new(
            user.Id,
            user.Username,
            tokens.AccessToken,
            tokens.RefreshToken,
            user.PrivateKey,
            user.PublicKey,
            user.KeySalt,
            user.KeyKdf);

    private static bool IsValidKeyMetadata(string salt, string keyKdf)
    {
        if (string.IsNullOrEmpty(salt) || salt.Length != 24 || keyKdf != UserService.CurrentKeyKdf)
        {
            return false;
        }

        try
        {
            return Convert.FromBase64String(salt).Length == 16;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private static bool IsSecureAuthenticationRequest(HttpContext request) =>
        request.Request.IsHttps ||
        request.Connection.RemoteIpAddress is { } remoteIp && System.Net.IPAddress.IsLoopback(remoteIp);
}