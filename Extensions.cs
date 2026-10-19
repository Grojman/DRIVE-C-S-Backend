using System.Text;
using System.Text.Json;

public static class Extensions
{
    public static int GetUserId(this HttpContext context) => (int)context.Items[AuthMiddleware.USER_ID_KEY]!;
    public static string GetSessionId(this HttpContext context) => (string)context.Items[AuthMiddleware.SESSION_KEY]!;

    public static string Decode(this string value)
    {
        return Encoding.UTF8.GetString(Convert.FromBase64String(value));
    }
    public static async Task<T?> ReadBase64JsonAsync<T>(this HttpRequest request)
    {
        using var reader = new StreamReader(request.Body);
        var encoded = (await reader.ReadToEndAsync()).Trim();
        try
        {
            var json = Encoding.UTF8.GetString(Convert.FromBase64String(encoded));
            return JsonSerializer.Deserialize<T>(json, JsonSerializerOptions.Web);
        }
        catch (Exception e) when (e is FormatException or JsonException)
        {
            return default;
        }
    }

    public static string? ReadBase64Query(this HttpRequest request, string key)
    {
        var encoded = request.Query[key].ToString();
        if (string.IsNullOrEmpty(encoded)) return null;
        try { return Encoding.UTF8.GetString(Convert.FromBase64String(encoded)); }
        catch (FormatException) { return null; }
    }

}