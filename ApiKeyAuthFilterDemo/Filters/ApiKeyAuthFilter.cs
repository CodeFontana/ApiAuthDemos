using ApiKeyAuthFilterDemo.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Primitives;

namespace ApiKeyAuthFilterDemo.Filters;

public class ApiKeyAuthFilter : Attribute, IAuthorizationFilter
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
        List<ApiKeyModel> validKeys = _config.GetSection("ApiKeys").Get<List<ApiKeyModel>>();

        KeyValuePair<string, StringValues> apiKeyHeader = context.HttpContext.Request.Headers
            .FirstOrDefault(h => validKeys.Select(
                x => x.HeaderName.ToLower()).Contains(h.Key.ToLower()));

        if (apiKeyHeader.Equals(default(KeyValuePair<string, StringValues>)))
        {
            context.Result = new UnauthorizedObjectResult("Missing API key");
            return;
        }

        ApiKeyModel matchingKey = validKeys
            .Where(x => x.HeaderName.ToLower().Equals(apiKeyHeader.Key.ToLower()))
            .Where(x => x.ApiKey.ToLower().Equals(apiKeyHeader.Value[0].ToLower()))
            .FirstOrDefault();

        if (matchingKey is null)
        {
            context.Result = new UnauthorizedObjectResult("Invalid API key");
            return;
        }
    }
}
