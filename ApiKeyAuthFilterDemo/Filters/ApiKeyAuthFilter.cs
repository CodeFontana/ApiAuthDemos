using ApiKeyAuthFilterDemo.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Primitives;

namespace ApiKeyAuthFilterDemo.Filters;

public sealed class ApiKeyAuthFilter : Attribute, IAuthorizationFilter
{
    // Using the ServiceFilter approach,
    // [ServiceFilter(typeof(ApiKeyAuthFilter))]
    // ... you can inject IConfiguration via the constructor:

    private readonly IConfiguration _config;

    public ApiKeyAuthFilter(IConfiguration configuration)
    {
        _config = configuration;
    }

    public void OnAuthorization(AuthorizationFilterContext context)
    {
        // Using the Attribute approach:
        // [ApiKeyAuthFilter]
        // ... you can obtain the IConfiguration from the HttpContext:
        //IConfiguration _config = context.HttpContext.RequestServices.GetService<IConfiguration>();
        List<ApiKeyModel> validKeys = _config.GetSection("ApiKeys")?.Get<List<ApiKeyModel>>()
            ?? throw new InvalidOperationException("ApiKeys section is missing from configuration");

        KeyValuePair<string, StringValues> apiKeyHeader = context.HttpContext.Request.Headers
            .FirstOrDefault(h => validKeys.Select(
                x => x.HeaderName.ToLower()).Contains(h.Key.ToLower()));

        if (apiKeyHeader.Equals(default(KeyValuePair<string, StringValues>)))
        {
            context.Result = new UnauthorizedObjectResult("Request missing API key header");
            return;
        }

        ApiKeyModel? matchingKey = validKeys
            .Where(x => x.HeaderName.ToLower().Equals(apiKeyHeader.Key.ToLower()))
            .Where(x => x.ApiKey.Equals(apiKeyHeader.Value[0]))
            .FirstOrDefault();

        if (matchingKey is null)
        {
            context.Result = new UnauthorizedObjectResult("Invalid API key");
            return;
        }
    }
}
