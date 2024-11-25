using Microsoft.Extensions.Options;

namespace CombinedAuthDemo.Authentication.ApiKeyAuth;

public class ApiKeyAuthenticationPostConfigureOptions : IPostConfigureOptions<ApiKeyAuthenticationOptions>
{
    public void PostConfigure(string? name, ApiKeyAuthenticationOptions options) { }
};
