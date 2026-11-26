using System.Runtime.CompilerServices;
using Microsoft.Data.Sqlite;

public static class DataBaseService
{
    public const string ConnectionString = "Data Source=Data/database.db";
    private static SqliteConnection _connection = null!;

    // La conexión es compartida y SqliteConnection no es thread-safe: con las subidas por trozos llegan
    // varias peticiones a la vez, así que todo acceso (y las transacciones completas) pasa por este lock.
    // Monitor es reentrante, por lo que una transacción puede volver a pedirlo desde el mismo hilo.
    public static readonly object Lock = new();

    public static void Start()
    {
        Directory.CreateDirectory("Data");
        _connection = new SqliteConnection(ConnectionString);
        _connection.Open();

        Execute("PRAGMA foreign_keys = ON", new Dictionary<string, string>());
        CheckDatabase();
        Console.WriteLine("======================");
        Console.WriteLine("Base de datos abierta");
        Console.WriteLine("======================");
    }

    public static void Stop()
    {
        lock (Lock) _connection.Close();
    }

    // Se materializa la lista dentro del lock: un iterador perezoso ejecutaría la consulta fuera de él
    public static IEnumerable<T> ReadMany<T>(string query, Dictionary<string, string> args)
    {
        return ReadMany(query, args, reader => (T)Convert.ChangeType(reader[0], typeof(T)));
    }

    public static IEnumerable<T> ReadMany<T>(string query, Dictionary<string, string> args, Func<SqliteDataReader, T> map)
    {
        lock (Lock)
        {
            using var command = CreateCommand(query, args);
            using var reader = command.ExecuteReader();

            var result = new List<T>();
            while (reader.Read())
            {
                result.Add(map(reader));
            }
            return result;
        }
    }

    public static T ReadOne<T>(string query, Dictionary<string, string> args, Func<SqliteDataReader, T> map)
    {
        lock (Lock)
        {
            using var command = CreateCommand(query, args);
            using var reader = command.ExecuteReader();

            if (reader.Read())
            {
                return map(reader);
            }

            throw new InvalidOperationException("No result found");
        }
    }

    public static T ReadOne<T>(string query, Dictionary<string, string> args)
    {
        return ReadOne(query, args, reader => (T)Convert.ChangeType(reader[0], typeof(T)));
    }

    public static void Execute(string query, Dictionary<string, string> args)
    {
        ExecuteNonQuery(query, args);
    }

    public static int ExecuteNonQuery(string query, Dictionary<string, string> args)
    {
        lock (Lock)
        {
            using var command = CreateCommand(query, args);
            return command.ExecuteNonQuery();
        }
    }

    private static SqliteCommand CreateCommand(string query, Dictionary<string, string> args)
    {
        var command = _connection.CreateCommand();
        command.CommandText = query;
        foreach (var arg in args)
        {
            command.Parameters.AddWithValue(arg.Key, arg.Value);
        }
        return command;
    }

    public static void CheckDatabase()
    {
        UserService.CreateTable();
        FileDataService.CreateTables();
        UploadService.CreateTables();
        JwtService.CreateTable();
    }
}
