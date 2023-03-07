using ApiKeyAuthDemo.Interfaces;
using ApiKeyAuthDemo.Models;

namespace ApiKeyAuthDemo.ApiKeyAuth;

public class ApiKeyAuthenticationService : IApiKeyAuthenticationService
{
    private readonly IConfiguration _config;

    public ApiKeyAuthenticationService(IConfiguration configuration)
    {
        _config = configuration;
    }

    public Task<bool> IsValidAsync(string headerName, string headerValue)
    {
        List<ApiKeyModel> configuredApiKeys = _config.GetSection("ApiKeys").Get<List<ApiKeyModel>>();

        ApiKeyModel apiKey = configuredApiKeys
            .Where(x => x.HeaderName.ToLower().Equals(headerName.ToLower()))
            .Where(x => x.ApiKey.ToLower().Equals(headerValue.ToLower()))
            .FirstOrDefault();

        return Task.FromResult(apiKey != null);
    }
}
