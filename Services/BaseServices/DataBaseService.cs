using System.Runtime.CompilerServices;
using Microsoft.Data.Sqlite;

public static class DataBaseService
{
    public const string ConnectionString = "Data Source=Data/database.db";
    private static SqliteConnection _connection;

    public static void Start()
    {
        _connection = new SqliteConnection(ConnectionString);
        _connection.Open();   
    }

    public static void Stop()
    {
        _connection.Close();
    }

    public static IEnumerable<T> ReadMany<T>(string query, Dictionary<string, string> args)
    {
        using var command = _connection.CreateCommand();
        command.CommandText = query;
        foreach(var arg in args)
        {
            command.Parameters.AddWithValue(arg.Key, arg.Value);
        }

        using var reader = command.ExecuteReader();

        while(reader.Read())
        {
            yield return (T)Convert.ChangeType(reader[0], typeof(T));
        }
    }

    public static T ReadOne<T>(string query, Dictionary<string, string> args)
    {
        using var command = _connection.CreateCommand();
        command.CommandText = query;
        foreach(var arg in args)
        {
            command.Parameters.AddWithValue(arg.Key, arg.Value);
        }

        using var reader = command.ExecuteReader();

        if(reader.Read())
        {
            return (T)Convert.ChangeType(reader[0], typeof(T));
        }

        throw new InvalidOperationException("No result found");
    }

    public static void Execute(string query, Dictionary<string, string> args)
    {
        using var command = _connection.CreateCommand();
        command.CommandText = query;
        foreach(var arg in args)
        {
            command.Parameters.AddWithValue(arg.Key, arg.Value);
        }

        command.ExecuteNonQuery();
    }

    public static void CheckDatabase()
    {
        //TODO: REPLACE
        Execute("CREATE TABLE IF NOT EXISTS Users (Id INTEGER PRIMARY KEY AUTOINCREMENT, Name TEXT NOT NULL, Email TEXT NOT NULL UNIQUE)", new Dictionary<string, string>());
    }
}