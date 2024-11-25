using ApiKeyMiddlewareAuthDemo.Models;
using Microsoft.Extensions.Primitives;

namespace ApiKeyMiddlewareAuthDemo.Middleware;

public sealed class ApiKeyAuthMiddleware
{
    private readonly RequestDelegate _next;
    private readonly IConfiguration _config;

    public ApiKeyAuthMiddleware(RequestDelegate next, IConfiguration configuration)
    {
        _next = next;
        _config = configuration;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        List<ApiKeyModel> validKeys = _config.GetSection("ApiKeys")?.Get<List<ApiKeyModel>>()
            ?? throw new InvalidOperationException("ApiKeys section is missing from configuration");

        KeyValuePair<string, StringValues> apiKeyHeader = context.Request.Headers
            .FirstOrDefault(h => validKeys.Select(
                x => x.HeaderName.ToLower()).Contains(h.Key.ToLower()));

        if (apiKeyHeader.Equals(default(KeyValuePair<string, StringValues>)))
        {
            context.Response.StatusCode = 401;
            await context.Response.WriteAsync("Request header missing API key");
            return;
        }

        ApiKeyModel? matchingKey = validKeys
            .Where(x => x.HeaderName.ToLower().Equals(apiKeyHeader.Key.ToLower()))
            .Where(x => x.ApiKey.Equals(apiKeyHeader.Value[0]))
            .FirstOrDefault();

        if (matchingKey is null)
        {
            context.Response.StatusCode = 401;
            await context.Response.WriteAsync("Invalid API key");
            return;
        }

        await _next(context);
    }
}
