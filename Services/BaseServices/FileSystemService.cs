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

    public static bool RemoveFile(string route)
    {
        var path = Path.Combine(BaseDirectory, route);
        try
        {
            File.Delete(path);
            return true;
        } catch (Exception)
        {
            return false;
        }
    }
    public static bool RemoveDirectory(string route)
    {
        var path = Path.Combine(BaseDirectory, route);
        try
        {
            Directory.Delete(path);
            return true;
        } catch (Exception)
        {
            return false;
        }
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

    public static bool CreateFile(string route, string fileData)
    {
        string filePath = Path.Combine(BaseDirectory, route);
        try
        {
            File.WriteAllText(filePath, fileData);
            return true;
        }
        catch (Exception)
        {
            return false;
        }
    }

    public static bool ReWriteFile(string route, string newContent)
    {
        string filePath = Path.Combine(BaseDirectory, route);
        if (!File.Exists(filePath)) return false;

        try
        {
            File.WriteAllText(route, newContent);
            return true;
        } catch (Exception)
        {
            return false;
        }
    }

    public static string[] GetFilesAndDirectories(string route)
    {
        string directoryPath = Path.Combine(BaseDirectory, route);
        if (!Directory.Exists(directoryPath))
        {
            return Array.Empty<string>();
        }

        var files = Directory.GetFiles(directoryPath);
        var directories = Directory.GetDirectories(directoryPath);
        return [.. files.Concat(directories).Select(path => Path.GetFileNameWithoutExtension(path))];
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