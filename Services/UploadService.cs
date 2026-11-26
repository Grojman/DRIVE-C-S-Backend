// Subidas por trozos. Flujo:
//   1. Init: se crea una sesión (y, si el archivo es nuevo, su FileInfo en estado 'Pending')
//   2. WriteChunk: cada trozo cifrado llega en su propia petición y se guarda en Server/uploads/{uploadId}/{n}
//   3. Complete: si están todos, el directorio de la sesión pasa a ser Server/{owner}/{fileId} y el archivo queda 'Ready'
//   Abort (o la limpieza de sesiones inactivas) borra los trozos y la reserva del nombre.
// El servidor nunca descifra nada: solo comprueba que los trozos esperados existen y tienen un tamaño razonable.
public static class UploadService
{
    // Límites del tamaño de trozo en texto plano (el cliente elige entre 4 MB y 50 MB según el archivo)
    public const int MinChunkSize = 1024;
    public const int MaxChunkSize = 64 * 1024 * 1024;
    public const int MaxChunkCount = 10_000;
    // Una sesión sin actividad durante este tiempo se considera abandonada
    public static readonly TimeSpan StaleAfter = TimeSpan.FromHours(1);

    private const string UploadsRoot = "uploads";
    private const string DateFormat = "yyyy-MM-dd HH:mm:ss";

    // Completar y abortar mueven directorios y tocan la BD: se serializan para que no se pisen entre sí
    private static readonly object FinalizeLock = new();

    public enum Result { Ok, NotFound, BadRequest, Conflict, TooLarge }

    public record Session(int Id, int FileId, int OwnerId, bool IsNew, long Size, int ChunkCount, int ChunkSize, DateTime LastActivity);

    private const string CreateTableQuery = @"
        CREATE TABLE IF NOT EXISTS FileUploads (
            Id INTEGER PRIMARY KEY AUTOINCREMENT,
            FileId INTEGER NOT NULL,
            OwnerId INTEGER NOT NULL,
            IsNew INTEGER NOT NULL,
            Size INTEGER NOT NULL,
            ChunkCount INTEGER NOT NULL,
            ChunkSize INTEGER NOT NULL,
            LastActivity TEXT NOT NULL,
            FOREIGN KEY (FileId) REFERENCES FileInfo(Id) ON DELETE CASCADE
        )";
    private const string CreateSessionQuery = "INSERT INTO FileUploads (FileId, OwnerId, IsNew, Size, ChunkCount, ChunkSize, LastActivity) VALUES (@FileId, @OwnerId, @IsNew, @Size, @ChunkCount, @ChunkSize, @LastActivity)";
    private const string ReadSessionQuery = "SELECT Id, FileId, OwnerId, IsNew, Size, ChunkCount, ChunkSize, LastActivity FROM FileUploads WHERE Id = @Id";
    private const string ReadAllSessionsQuery = "SELECT Id, FileId, OwnerId, IsNew, Size, ChunkCount, ChunkSize, LastActivity FROM FileUploads";
    private const string SessionsForFileQuery = "SELECT Id FROM FileUploads WHERE FileId = @FileId";
    private const string TouchSessionQuery = "UPDATE FileUploads SET LastActivity = @LastActivity WHERE Id = @Id";
    private const string DeleteSessionQuery = "DELETE FROM FileUploads WHERE Id = @Id";
    // Pendientes sin sesión (p. ej. el proceso murió a mitad): nadie podrá completarlos
    private const string DeleteOrphanPendingQuery = "DELETE FROM FileInfo WHERE Status = 'Pending' AND Id NOT IN (SELECT FileId FROM FileUploads)";

    public static void CreateTables()
    {
        DataBaseService.Execute(CreateTableQuery, []);
        FileSystemService.CreateDirectory(UploadsRoot);
    }

    private static string SessionRoute(int uploadId) => Path.Combine(UploadsRoot, uploadId.ToString());
    private static string ChunkRoute(int uploadId, int index) => Path.Combine(SessionRoute(uploadId), index.ToString());
    public static string FileRoute(int ownerId, int fileId) => Path.Combine(ownerId.ToString(), fileId.ToString());
    public static string StoredChunkRoute(int ownerId, int fileId, int index) => Path.Combine(FileRoute(ownerId, fileId), index.ToString());

    // Lo cifrado ocupa el trozo comprimido + IV + etiqueta GCM. Deflate puede crecer un poco con datos
    // incomprimibles, así que se deja margen; cualquier cosa por encima se rechaza
    public static long MaxStoredChunkBytes(int chunkSize) => chunkSize + chunkSize / 64L + 4096;

    public static int ExpectedChunkCount(long size, int chunkSize) => size == 0 ? 1 : (int)Math.Min(int.MaxValue, (size + chunkSize - 1) / chunkSize);

    public static bool ValidLayout(long size, int chunkSize, int chunkCount) =>
        size >= 0 &&
        chunkSize is >= MinChunkSize and <= MaxChunkSize &&
        chunkCount is >= 1 and <= MaxChunkCount &&
        chunkCount == ExpectedChunkCount(size, chunkSize);

    // Archivo nuevo. Las claves deben incluir al propio dueño o no podría volver a descargarlo
    public static (Result, Session?) InitNew(int userId, string fileName, string filePath, long size, int chunkSize, int chunkCount, UserFileKey[] keys)
    {
        CleanupStale();

        if (!ValidLayout(size, chunkSize, chunkCount) || !ValidName(fileName) || string.IsNullOrEmpty(filePath) ||
            keys.Length == 0 || !keys.Any(k => k.UserId == userId) || keys.Any(k => string.IsNullOrEmpty(k.Key)))
        {
            return (Result.BadRequest, null);
        }
        if (!FileDataService.FolderExists(userId, filePath)) return (Result.NotFound, null);

        int uploadId = -1, fileId = -1;
        var now = DateTime.Now;
        bool conflict = false;

        bool ok = FileDataService.RunInTransaction(() =>
        {
            if (FileDataService.GetFileInfoByNamePath(userId, fileName, filePath) != -1)
            {
                conflict = true;
                throw new InvalidOperationException("Name already taken");
            }
            var info = new FileInfo(-1, fileName, filePath, size, [], now, now, FileType.File);
            fileId = FileDataService.CreatePendingFileInfo(userId, info, keys);
            if (fileId == -1) throw new InvalidOperationException("Could not create file info");
            uploadId = InsertSession(fileId, userId, true, size, chunkCount, chunkSize, now);
        });

        if (!ok) return (conflict ? Result.Conflict : Result.BadRequest, null);

        FileSystemService.CreateDirectory(SessionRoute(uploadId));
        return (Result.Ok, new Session(uploadId, fileId, userId, true, size, chunkCount, chunkSize, now));
    }

    // Reemplazar el contenido de un archivo propio (edición o regeneración de la clave)
    public static (Result, Session?) InitReplace(int userId, int fileId, long size, int chunkSize, int chunkCount)
    {
        CleanupStale();

        if (!ValidLayout(size, chunkSize, chunkCount)) return (Result.BadRequest, null);

        var storage = FileDataService.GetStorageInfo(fileId);
        if (storage is null || storage.OwnerId != userId || storage.FileType != FileType.File || storage.Status != "Ready")
        {
            return (Result.NotFound, null);
        }

        var now = DateTime.Now;
        int uploadId = InsertSession(fileId, userId, false, size, chunkCount, chunkSize, now);
        FileSystemService.CreateDirectory(SessionRoute(uploadId));
        return (Result.Ok, new Session(uploadId, fileId, userId, false, size, chunkCount, chunkSize, now));
    }

    public static async Task<Result> WriteChunk(int userId, int uploadId, int index, HttpRequest request, CancellationToken token)
    {
        var session = GetActiveSession(userId, uploadId);
        if (session is null) return Result.NotFound;
        if (index < 0 || index >= session.ChunkCount) return Result.BadRequest;

        long max = MaxStoredChunkBytes(session.ChunkSize);
        if (request.ContentLength is long length && length > max) return Result.TooLarge;
        // Un trozo vacío nunca es válido: como mínimo lleva IV + etiqueta
        if (request.ContentLength == 0) return Result.BadRequest;

        try
        {
            if (!await FileSystemService.WriteStreamAsync(ChunkRoute(uploadId, index), request.Body, max, token))
            {
                return Result.TooLarge;
            }
        }
        catch (Exception e) when (e is DirectoryNotFoundException or IOException)
        {
            // La sesión se abortó o completó mientras se escribía este trozo
            return GetActiveSession(userId, uploadId) is null ? Result.NotFound : Result.Conflict;
        }

        DataBaseService.Execute(TouchSessionQuery, new Dictionary<string, string>
        {
            { "@Id", uploadId.ToString() },
            { "@LastActivity", DateTime.Now.ToString(DateFormat) }
        });
        return Result.Ok;
    }

    // Devuelve los índices que faltan, para que el cliente pueda reenviarlos
    public static (Result, int[] Missing) Complete(int userId, int uploadId, UserFileKey[]? keys)
    {
        if (keys is not null && (keys.Length == 0 || !keys.Any(k => k.UserId == userId) || keys.Any(k => string.IsNullOrEmpty(k.Key))))
        {
            return (Result.BadRequest, []);
        }

        lock (FinalizeLock)
        {
            var session = GetActiveSession(userId, uploadId);
            if (session is null) return (Result.NotFound, []);

            var missing = Enumerable.Range(0, session.ChunkCount)
                .Where(i => !File.Exists(FileSystemService.FullPath(ChunkRoute(uploadId, i))))
                .ToArray();
            if (missing.Length > 0) return (Result.Conflict, missing);

            var target = FileRoute(userId, session.FileId);
            var backup = $"{target}.replaced-{uploadId}";
            FileSystemService.CreateDirectory(userId.ToString());

            bool hadPrevious = FileSystemService.Exists(target);
            try
            {
                if (hadPrevious) FileSystemService.MoveEntry(target, backup);
                FileSystemService.MoveEntry(SessionRoute(uploadId), target);
            }
            catch (IOException)
            {
                if (hadPrevious && !FileSystemService.Exists(target) && FileSystemService.Exists(backup))
                {
                    FileSystemService.MoveEntry(backup, target);
                }
                return (Result.Conflict, []);
            }

            bool ok = FileDataService.FinishChunkedStorage(
                userId, session.FileId, uploadId, session.ChunkCount, session.ChunkSize, session.Size, keys,
                () => DataBaseService.Execute(DeleteSessionQuery, new Dictionary<string, string> { { "@Id", uploadId.ToString() } }));

            if (!ok)
            {
                // Se deja todo como estaba: el contenido anterior vuelve a su sitio y la sesión sigue abierta
                FileSystemService.MoveEntry(target, SessionRoute(uploadId));
                if (hadPrevious) FileSystemService.MoveEntry(backup, target);
                return (Result.Conflict, []);
            }

            if (hadPrevious) FileSystemService.RemoveEntry(backup);
            return (Result.Ok, []);
        }
    }

    public static Result Abort(int userId, int uploadId)
    {
        lock (FinalizeLock)
        {
            var session = GetSession(uploadId);
            if (session is null || session.OwnerId != userId) return Result.NotFound;
            Discard(session);
            return Result.Ok;
        }
    }

    // Al borrar un archivo se descartan también sus subidas en curso
    public static void DiscardForFile(int fileId)
    {
        lock (FinalizeLock)
        {
            var ids = DataBaseService.ReadMany(SessionsForFileQuery,
                new Dictionary<string, string> { { "@FileId", fileId.ToString() } }, r => r.GetInt32(0));
            foreach (var id in ids)
            {
                FileSystemService.RemoveEntry(SessionRoute(id));
                DataBaseService.Execute(DeleteSessionQuery, new Dictionary<string, string> { { "@Id", id.ToString() } });
            }
        }
    }

    public static void CleanupStale()
    {
        lock (FinalizeLock)
        {
            var limit = DateTime.Now - StaleAfter;
            var sessions = DataBaseService.ReadMany(ReadAllSessionsQuery, [], MapSession);
            foreach (var session in sessions.Where(s => s.LastActivity < limit))
            {
                Discard(session);
            }

            DataBaseService.Execute(DeleteOrphanPendingQuery, []);

            // Directorios de sesiones que ya no existen en la BD
            var live = DataBaseService.ReadMany(ReadAllSessionsQuery, [], MapSession).Select(s => s.Id.ToString()).ToHashSet();
            var root = FileSystemService.FullPath(UploadsRoot);
            if (!Directory.Exists(root)) return;
            foreach (var dir in Directory.GetDirectories(root))
            {
                if (!live.Contains(Path.GetFileName(dir)))
                {
                    try { Directory.Delete(dir, true); } catch (IOException) { }
                }
            }
        }
    }

    private static void Discard(Session session)
    {
        FileSystemService.RemoveEntry(SessionRoute(session.Id));
        FileDataService.RunInTransaction(() =>
        {
            DataBaseService.Execute(DeleteSessionQuery, new Dictionary<string, string> { { "@Id", session.Id.ToString() } });
            if (session.IsNew) FileDataService.DeletePendingFileInfo(session.FileId);
        });
    }

    private static Session? GetActiveSession(int userId, int uploadId)
    {
        var session = GetSession(uploadId);
        if (session is null || session.OwnerId != userId) return null;
        return session.LastActivity < DateTime.Now - StaleAfter ? null : session;
    }

    private static Session? GetSession(int uploadId)
    {
        try
        {
            return DataBaseService.ReadOne(ReadSessionQuery, new Dictionary<string, string> { { "@Id", uploadId.ToString() } }, MapSession);
        }
        catch (InvalidOperationException)
        {
            return null;
        }
    }

    private static int InsertSession(int fileId, int ownerId, bool isNew, long size, int chunkCount, int chunkSize, DateTime now)
    {
        return FileDataService.RunInTransactionWithResult(() =>
        {
            DataBaseService.Execute(CreateSessionQuery, new Dictionary<string, string>
            {
                { "@FileId", fileId.ToString() },
                { "@OwnerId", ownerId.ToString() },
                { "@IsNew", isNew ? "1" : "0" },
                { "@Size", size.ToString() },
                { "@ChunkCount", chunkCount.ToString() },
                { "@ChunkSize", chunkSize.ToString() },
                { "@LastActivity", now.ToString(DateFormat) }
            });
            return DataBaseService.ReadOne<int>("SELECT last_insert_rowid()", []);
        });
    }

    private static Session MapSession(Microsoft.Data.Sqlite.SqliteDataReader r) => new(
        r.GetInt32(0), r.GetInt32(1), r.GetInt32(2), r.GetInt32(3) == 1, r.GetInt64(4), r.GetInt32(5), r.GetInt32(6),
        DateTime.Parse(r.GetString(7)));

    public static bool ValidName(string? name) =>
        !string.IsNullOrWhiteSpace(name) && !name.Contains('/') && !name.Contains('\\') && !name.Contains("..") && name.Length <= 255;
}
