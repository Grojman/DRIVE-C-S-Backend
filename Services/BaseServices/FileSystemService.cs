public static class FileSystemService
{
    private const string BaseDirectory = "./Server";
    public static void Start()
    {
        if(!Directory.Exists(BaseDirectory))
        {
            Directory.CreateDirectory(BaseDirectory);
        }
    }

    // Ruta absoluta dentro de ./Server (Results.File necesita rutas absolutas)
    public static string FullPath(string route) => Path.GetFullPath(Path.Combine(BaseDirectory, route));

    public static bool Exists(string route)
    {
        var path = FullPath(route);
        return File.Exists(path) || Directory.Exists(path);
    }

    // Borra un archivo o un directorio completo (formato legado = archivo, formato por trozos = directorio)
    public static bool RemoveEntry(string route)
    {
        var path = FullPath(route);
        try
        {
            if (Directory.Exists(path)) Directory.Delete(path, true);
            else File.Delete(path);
            return true;
        } catch (Exception)
        {
            return false;
        }
    }

    // Mueve un archivo o directorio. El destino no debe existir
    public static void MoveEntry(string fromRoute, string toRoute)
    {
        var from = FullPath(fromRoute);
        var to = FullPath(toRoute);
        if (Directory.Exists(from)) Directory.Move(from, to);
        else File.Move(from, to);
    }

    public static bool CreateDirectory(string route)
    {
        string filePath = Path.Combine(BaseDirectory, route);
        try
        {
            Directory.CreateDirectory(filePath);
            return true;
        } catch(Exception)
        {
            return false;
        }
    }

    // Copia el cuerpo de la petición a disco sin cargarlo entero en memoria. Se escribe en un archivo temporal
    // y se renombra al final, así un trozo a medio escribir nunca se confunde con uno completo.
    // Devuelve false si el cuerpo supera maxBytes (y no deja nada escrito)
    public static async Task<bool> WriteStreamAsync(string route, Stream source, long maxBytes, CancellationToken token)
    {
        var target = FullPath(route);
        var temp = $"{target}.part-{Guid.NewGuid():N}";
        try
        {
            await using (var output = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None, 81920, true))
            {
                var buffer = new byte[81920];
                long total = 0;
                int read;
                while ((read = await source.ReadAsync(buffer, token)) > 0)
                {
                    total += read;
                    if (total > maxBytes) return false;
                    await output.WriteAsync(buffer.AsMemory(0, read), token);
                }
            }
            File.Move(temp, target, true);
            return true;
        }
        finally
        {
            if (File.Exists(temp)) File.Delete(temp);
        }
    }

    public static string ReadFileContent(string route)
    {
        string filePath = Path.Combine(BaseDirectory, route);
        if (!File.Exists(filePath))
        {
            throw new FileNotFoundException($"File not found: {filePath}");
        }

        return File.ReadAllText(filePath);
    }
}
