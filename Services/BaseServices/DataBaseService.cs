using System.Runtime.CompilerServices;
using Microsoft.Data.Sqlite;

public static class DataBaseService
{
    public const string ConnectionString = "Data Source=Data/database.db";
    private static SqliteConnection _connection;

    public static void Start()
    {
        Directory.CreateDirectory("Data");
        _connection = new SqliteConnection(ConnectionString);
        _connection.Open();

        Execute("PRAGMA foreign_keys = ON", new Dictionary<string, string>());
        CheckDatabase();
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

    public static IEnumerable<T> ReadMany<T>(string query, Dictionary<string, string> args, Func<SqliteDataReader, T> map)
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
            yield return map(reader);
        }
    }

    public static T ReadOne<T>(string query, Dictionary<string, string> args, Func<SqliteDataReader, T> map)
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
            return map(reader);
        }

        throw new InvalidOperationException("No result found");
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
        UserService.CreateTable();
        FileDataService.CreateTables();
    }
}