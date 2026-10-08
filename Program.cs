
using System.Collections;
using System.Text.Json.Serialization;

internal class Program
{   

    public record LoggedInUser(int Id, string Name, string CurrentId, string PrivateKey, string PublicKey);

    private static void Main(string[] args)
    {
        DataBaseService.Start();
        FileSystemService.Start();
        var builder = WebApplication.CreateBuilder(args);
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

        var app = builder.Build();

        app.UseCors();

        app.UseMiddleware<AuthMiddleware>();

        app.MapGet("/", () => "Hello World!");

        var securedGroup = app.MapGroup("").RequireSession();

        //- "/login": POST: Usuario, Contraseña
        app.MapPost("/login", async(HttpContext request) =>
        {
            var person = await request.Request.ReadBase64JsonAsync<Usuario_login_DTO>();
            
            if(person is not null)
            {
                if (UserService.UserExists(person.user, person.password))
                {   
                    UserService.UserDB? DBuser = UserService.GetUser(person.user, person.password);
                    if(DBuser is not null)
                    {
                        string id = UserService.addKey(DBuser.Id); //Results.Ok(new { success = true, message = "Authenticated"});
                        LoggedInUser new_user = new (DBuser.Id, person.user, id, DBuser.PrivateKey, DBuser.PublicKey);
                        return Results.Ok(new_user);
                    }
                    return Results.Unauthorized();
                }
                
            }
            return Results.BadRequest();
        });


        //- "/signin": POST: usuario Contraseña pk Pk
        app.MapPost("/signin", async(HttpContext request) =>
        {
            var person = await request.Request.ReadBase64JsonAsync<Usuario_registro_DTO>();
            if(person is not null)
            {
                if (UserService.IsUsernameTaken(person.user)) return Results.Conflict();
                if(UserService.postUser(person.user, person.password, person.private_key, person.public_key))
                {
                    UserService.UserDB? DBuser = UserService.GetUser(person.user, person.password);
                    if (DBuser != null)
                    {
                        string id = UserService.addKey(DBuser.Id);
                        LoggedInUser new_user = new (DBuser.Id, person.user, id, DBuser.PrivateKey, DBuser.PublicKey);
                        return Results.Ok(new_user);
                    }
                    return Results.Conflict();
                }
            }
            return Results.Unauthorized();
        });

        //  "/username/{username}": GET: Usuario 
        app.MapGet("/username/{username}", async(string username) =>
        {
            return Results.Ok(UserService.IsUsernameTaken(username));
        });

        //  "/logout": POST: userId
        securedGroup.MapPost("/logout", async(HttpContext request) =>
        {
            var id = request.GetSessionId();
            if(UserService.IsConnected(id))
            {
                UserService.deleteKey(id);
                return Results.Ok("Succesfully logged out");
            }
            return Results.BadRequest("Error at logging out.");
        });

        //  - "/files" GET: userId, Ruta (SOLO METADATOS)[Vector]
        securedGroup.MapGet("/files", async(IConfiguration config ,HttpContext request, int FileId, string targetDirectory) =>
        {
            if (FileId> 0)
            {
                var userId = request.GetUserId();
                IEnumerable files = FileDataService.GetFilesInPath(userId, targetDirectory);
                return files;
            }
            return null;
            
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
                var folderInfo = new FileInfo(-1, info.FileName, info.FilePath, info.Size, info.data.EncriptedKeys, DateTime.Now, DateTime.Now, FileType.File);
                if (FileService.CreateFile(userId, folderInfo, info.data.FileData))
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
                        PrivateKeys = transferInfo.data.EncriptedKeys,
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

            if (data.EncryptedKeys.Length == 0) return Results.BadRequest("At least one key is required");

            var updated = currentFiledata with
            {
                Name = data.FileName ?? currentFiledata.Name,
                Path = data.FilePath ?? currentFiledata.Path,
                PrivateKeys = data.EncryptedKeys ?? currentFiledata.PrivateKeys,
                ModifiedAt = DateTime.Now
            };

            bool renamedOrMoved = updated.Name != currentFiledata.Name || updated.Path != currentFiledata.Path;
            if (renamedOrMoved)
            {
                if (!FileDataService.FolderExists(userId, updated.Path)) return Results.BadRequest("Destination folder not found");
                if (FileDataService.GetFileInfoByNamePath(userId, updated.Name, updated.Path) != -1) return Results.BadRequest("A file with that name already exists");
            }

            var result = updated.FileType == FileType.File ?
                         FileDataService.UpdateFileInfo(userId, updated) :
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
}   