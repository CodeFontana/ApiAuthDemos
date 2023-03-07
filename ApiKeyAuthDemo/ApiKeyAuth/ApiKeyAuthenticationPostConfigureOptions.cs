using Microsoft.Extensions.Options;

namespace ApiKeyAuthDemo.ApiKeyAuth;

public class ApiKeyAuthenticationPostConfigureOptions : IPostConfigureOptions<ApiKeyAuthenticationOptions>
{
    public void PostConfigure(string name, ApiKeyAuthenticationOptions options) { }
};
