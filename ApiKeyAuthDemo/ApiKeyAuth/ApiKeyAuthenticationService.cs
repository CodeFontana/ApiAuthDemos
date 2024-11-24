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
        List<ApiKeyModel> configuredApiKeys = _config.GetSection("ApiKeys")?.Get<List<ApiKeyModel>>()
            ?? throw new InvalidOperationException("ApiKeys is missing from configuration");

        ApiKeyModel? apiKey = configuredApiKeys
            .Where(x => x.HeaderName.Equals(
                headerName,
                StringComparison.InvariantCultureIgnoreCase)
                && x.ApiKey.Equals(headerValue))
            .FirstOrDefault();

        return Task.FromResult(apiKey != null);
    }
}
