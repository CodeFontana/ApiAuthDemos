using Microsoft.Extensions.Options;

namespace JwtAndApiKeyAuthDemo;

public class ApiKeyAuthenticationPostConfigureOptions : IPostConfigureOptions<ApiKeyAuthenticationOptions>
{
    public void PostConfigure(string name, ApiKeyAuthenticationOptions options) { }
};
