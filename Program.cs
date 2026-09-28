
using System.Diagnostics.Eventing.Reader;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.HttpLogging;
using Microsoft.AspNetCore.Razor.TagHelpers;
internal class Program
{   

    public record LoggedInUser(int Id, string Name, string CurrentId, string PrivateKey, string PublicKey);

    private static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);
        var app = builder.Build();

        app.MapGet("/", () => "Hello World!");

        //- "/login": POST: Usuario, Contraseña
        app.MapPost("/login", async(HttpContext request) =>
        {
            var person = await request.Request.ReadFromJsonAsync<Usuario_login_DTO>();
            
            if(person is not null)
            {
                if (UserService.UserExists(person.user, person.password))
                {   
                    UserService.UserDB? DBuser = UserService.GetUser(person.user, person.password);
                    if(DBuser is not null)
                    {
                        string id = UserService.addKey(DBuser.Id); //Results.Ok(new { success = true, message = "Authenticated"});
                        LoggedInUser new_user = new (DBuser.Id, person.user, id, DBuser.PrivateKey, DBuser.PublicKey);
                        return new_user;
                    }
                    return null;
                }
                
            }
            return null; //Results.Unauthorized();
        });


        //- "/signin": POST: usuario Contraseña pk Pk
        app.MapPost("/signin", async(HttpContext request) =>
        {
            var person = await request.Request.ReadFromJsonAsync<Usuario_registro_DTO>();
            if(person is not null)
            {
                if(UserService.postUser(person.name, person.password, person.private_key, person.public_key))
                {
                    UserService.UserDB? DBuser = UserService.GetUser(person.name, person.password);
                    if (DBuser != null)
                    {
                        string id = UserService.addKey(DBuser.Id);
                        LoggedInUser new_user = new (DBuser.Id, person.name, id, DBuser.PrivateKey, DBuser.PublicKey);
                        return Results.Accepted();
                    }
                    return Results.BadRequest();
                }
            }
            return Results.Unauthorized();
        });

        //  "/username/{username}": GET: Usuario 
        app.MapPost("/username/{username}", async(string username) =>
        {
            if (UserService.IsUsernameTaken(username))
            {

                return Results.Ok();
            }
            return Results.NotFound();
        });

        //  "/logout": POST: userId
        app.MapPost("/logout/{id}", async(int id) =>
        {
            if(UserService.IsConnected(id.ToString()))
            {
                UserService.deleteKey(id.ToString());
                return Results.Ok();
            }
            return Results.BadRequest();
        });

        //  - "/files" GET: userId, Ruta
        app.MapGet("/files", async(IConfiguration config ,HttpContext request) =>
        {
            var filePath = Path.Combine(config)
        });

        //  - "/file" GET: userId, Ruta
        app.MapGet();

        /*- "/file" POST: userId, Archivo,
        {
            nombre,
            id,
            fecha,
            ...
            clave,
            ruta,
            autorizaciones,
        } */

        /*- "/file" PUT: userId, Archivo,
        {
            nombre,
            id,
            fecha,
            ...
            clave,
            ruta
            autorizaciones,
        }*/

        //  - "/file" DELETE: userId, Ruta
        app.MapDelete("/file")

        //  - "/folder" POST: userId, Ruta, Nombre
        app.MapPost();

        //  - "/folder" DELETE: userId, Ruta
        app.MapDelete();

        // - "/folder" POST: userId, Ruta, Nombre
        app.MapPost() 

        



        



        

        app.Run();
    }

}   