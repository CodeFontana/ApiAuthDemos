using CombinedAuthDemo.Models;

namespace CombinedAuthDemo.Authentication.ApiKeyAuth;

public class ApiKeyAuthenticationService : IApiKeyAuthenticationService
{
    private readonly IConfiguration _config;

    public ApiKeyAuthenticationService(IConfiguration configuration)
    {
        _config = configuration;
    }

    public Task<bool> IsValidAsync(string headerName, string headerValue)
    {
        // Get list of API keys from configuration
        List<ApiKeyModel> configuredApiKeys = _config.GetSection("ApiKeys").Get<List<ApiKeyModel>>();

        // Isolate a matching API key, if any
        ApiKeyModel apiKey = configuredApiKeys
            .Where(x => x.HeaderName.ToLower().Equals(headerName.ToLower()))
            .Where(x => x.ApiKey.ToLower().Equals(headerValue.ToLower()))
            .FirstOrDefault();

        // Did we find a match?
        return Task.FromResult(apiKey != null);
    }
}
