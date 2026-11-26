// POST /file/upload. Sin FileId se crea un archivo nuevo (FileName, FilePath y Keys obligatorios);
// con FileId se reemplaza el contenido de un archivo propio
public record ChunkedUploadInitDTO(
    int? FileId,
    string? FileName,
    string? FilePath,
    long Size,
    int ChunkSize,
    int ChunkCount,
    UserFileKey[]? Keys);

public record ChunkedUploadSessionDTO(int UploadId, int FileId, int MaxChunkSize);

// POST /file/upload/complete. Keys solo si se quieren reemplazar las claves a la vez que el contenido
// (regeneración de clave), de forma atómica
public record ChunkedUploadCompleteDTO(int UploadId, UserFileKey[]? Keys);

public record ChunkedUploadMissingDTO(int[] MissingChunks);

public record ChunkedUploadAbortDTO(int UploadId);
