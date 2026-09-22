using System.Net.Http.Headers;
using System.Security.Authentication;

public static class UserService
{
    public record UserDB(int Id, string Username, string PublicKey, string PrivateKey);

    public static UserDB? GetUser(string name, string passowrd)
    {
        var query = "SELECT Id, Username, PublicKey, PrivateKey FROM Users WHERE Username=@username AND Password=@contrasena";
        var args = new Dictionary<string, string>
        {
            ["@username"]=name,
            ["@contrasena"]=passowrd
        };

        try
        {
            var count = DataBaseService.ReadOne<UserDB>(query, args);
            return count;
        }
        catch (InvalidOperationException)
        {
            return null; //Se trata como "Not Found"
        }
    }
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

    public static bool postUser(int id, string username, string password, string PrivateKey, string PublicKey)
    {
        var query="INSERT INTO Users(ID, USERNAME, PASSWORD, PRIVATEKEY, PUBLICKEY) VALUES( @id, @username, @password, @PrivateKey, @PublicKey)";
        var args = new Dictionary<string, string>
        {
            ["@id"]=id.ToString(),
            ["@username"]=username,
            ["@password"]=password,
            ["@PrivateKey"]=PrivateKey,
            ["@PublicKey"]=PublicKey
        };
        try
        {
            DataBaseService.Execute(query, args);
            return true;
        }
        catch(Exception)
        {
            return false;
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
