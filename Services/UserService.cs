using System.Net.Http.Headers;
using System.Security.Authentication;

public static class UserService
{
    public static bool IsUsernameTaken(string username)
    {
        var query = "SELECT COUNT(*) FROM Users WHERE Username = @username";
        var args = new Dictionary<string, string> { { "@username", username } };
        int count;
        try
        {
            count = DataBaseService.ReadOne<int>(query, args);
            
        } catch (InvalidOperationException)
        {
            return false;
        }
        return count > 0;
    }

    public static bool UserExists(string username, string contrasena)
    {   
        //Devolver 1 cuando exista el usuario
        var query = "SELECT COUNT(1) FROM Users WHERE Username=@username AND Password=@contrasena";
        var args = new Dictionary<string, string>
        {
            ["@username"]=username,
            ["@contrasena"]=contrasena
        };

        try
        {
            var count = DataBaseService.ReadOne<int>(query, args);
            return count>0;
        }
        catch (InvalidOperationException)
        {
            return false; //Se trata como "Not Found"
        }
    }

    public static int getUserId(string username, string password)
    {
        var query = "SELECT Id FROM Users WHERE Username=@username AND Password=@contrasena";
        var args = new Dictionary<string, string>
        {
            ["@username"]=username,
            ["@contrasena"]=password
        };

        try
        {
            var count = DataBaseService.ReadOne<int>(query, args);
            return count;
        }
        catch (InvalidOperationException)
        {
            return -1; //Se trata como "Not Found"
        }
    }

    public static int getUserId(string currentId) => UsuariosConectados[currentId];

    static Dictionary<string, int> UsuariosConectados = new();

    public static bool IsConnected(string userId)
    {
        return UsuariosConectados.ContainsKey(userId);
    }

    public static void deleteKey(string userId)
    {
        UsuariosConectados.Remove(userId);
    }

    public static string addKey(int userId)
    {
        Guid key = Guid.NewGuid();
        UsuariosConectados.Add(key.ToString(), userId);
        return key.ToString();
    }

}

