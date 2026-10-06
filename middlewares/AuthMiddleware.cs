public sealed class RequireSessionAttribute : Attribute { }

public class AuthMiddleware
{
    public const string USER_ID_KEY = "UserId";
    public const string SESSION_KEY = "SessionId";
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

        string? session = context.Request.Headers.Authorization;
        if (string.IsNullOrEmpty(session) || !UserService.TryGetUserId(session, out int userId))
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return;
        }

        // Handlers read these instead of parsing the header again
        context.Items[USER_ID_KEY] = userId;
        context.Items[SESSION_KEY] = session;

        await _next(context);
    }

}
public static class AuthEndpointExtensions
{
    public static TBuilder RequireSession<TBuilder>(this TBuilder builder) where TBuilder : IEndpointConventionBuilder
        => builder.WithMetadata(new RequireSessionAttribute());
}