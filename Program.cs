
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.HttpLogging;
using Microsoft.AspNetCore.Razor.TagHelpers;
internal class Program
{
    private static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);
        var app = builder.Build();

        app.MapGet("/", () => "Hello World!");

        //LOGIN GET
        app.MapPost("/login", async(HttpRequest request)=>
        {
            var person = await request.ReadFromJsonAsync<Usuario_login_DTO>();
            
            if(person is not null)
            {
                if (UserService.UserExists(person.user, person.password))
                {
                    UserService.addKey() //Results.Ok(new { success = true, message = "Authenticated"});
                }
                
            }
            return ""; //Results.Unauthorized();
        });

        /*app.MapPost("/signin", async(HttpRequest request) =>
        {
            
        }); */

        app.MapGet("/username/{body}" )

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