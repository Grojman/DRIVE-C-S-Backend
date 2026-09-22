
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

        //LOGIN GET
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

        

        /*app.MapPost("/signin", async(HttpRequest request) =>
        {
            
        }); */

        //app.MapGet("/username/{body}" )

        /*DEFINICIÓN DE LA API
        - "/login": POST: Usuario, Contraseña
        - "/signin": POST: usuario Contraseña (no todavía)
        - "/username/{body}": GET: Usuario 
        - "/logout": POST: userId
        - "/files" GET: userId, Ruta
        - "/file" GET: userId, Ruta
        - "/file" POST: userId, Archivo,
        {
            nombre,
            id,
            fecha,
            ...
            clave,
            ruta,
            autorizaciones,
        }
        - "/file" PUT: userId, Archivo,
        {
            nombre,
            id,
            fecha,
            ...
            clave,
            ruta
            autorizaciones,
        }
        - "/file" DELETE: userId, Ruta
        - "/folder" POST: userId, Ruta, Nombre
        - "/folder" DELETE: userId, Ruta
        - "/folder" POST: userId, Ruta, Nombre */

        app.Run();


    }

}   