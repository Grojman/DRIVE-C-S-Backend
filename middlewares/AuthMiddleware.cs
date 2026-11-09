public sealed class RequireSessionAttribute : Attribute { }

public class AuthMiddleware
{
    public const string USER_ID_KEY = "UserId";
    private readonly RequestDelegate _next;

    public AuthMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        if (context.GetEndpoint()?.Metadata.GetMetadata<RequireSessionAttribute>() is null)
        {
            await _next(context);
            return;
        }

        string? header = context.Request.Headers.Authorization;
        const string bearer = "Bearer ";
        if (string.IsNullOrEmpty(header) || !header.StartsWith(bearer, StringComparison.OrdinalIgnoreCase) ||
            !JwtService.TryValidateAccessToken(header[bearer.Length..].Trim(), out int userId))
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return;
        }

        // Handlers read this instead of parsing the token again
        context.Items[USER_ID_KEY] = userId;

        await _next(context);
    }

}
public static class AuthEndpointExtensions
{
    public static TBuilder RequireSession<TBuilder>(this TBuilder builder) where TBuilder : IEndpointConventionBuilder
        => builder.WithMetadata(new RequireSessionAttribute());
}