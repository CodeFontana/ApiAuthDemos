using JwtAndApiKeyAuthDemo;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace CombinedAuthDemo.Authentication.ApiKeyAuth;

public static class ApiKeyAuthenticationExtensions
{
    public static AuthenticationBuilder AddApiKey<TAuthService>(this AuthenticationBuilder builder)
        where TAuthService : class, IApiKeyAuthenticationService
    {
        return builder.AddApiKey<TAuthService>(ApiKeyAuthenticationDefaults.AuthenticationScheme, _ => { });
    }

    public static AuthenticationBuilder AddApiKey<TAuthService>(this AuthenticationBuilder builder, string authenticationScheme)
        where TAuthService : class, IApiKeyAuthenticationService
    {
        return builder.AddApiKey<TAuthService>(authenticationScheme, _ => { });
    }

    public static AuthenticationBuilder AddApiKey<TAuthService>(this AuthenticationBuilder builder, Action<ApiKeyAuthenticationOptions> configureOptions)
        where TAuthService : class, IApiKeyAuthenticationService
    {
        return builder.AddApiKey<TAuthService>(ApiKeyAuthenticationDefaults.AuthenticationScheme, configureOptions);
    }

    public static AuthenticationBuilder AddApiKey<TAuthService>(this AuthenticationBuilder builder, string authenticationScheme, Action<ApiKeyAuthenticationOptions> configureOptions)
        where TAuthService : class, IApiKeyAuthenticationService
    {
        builder.Services.AddSingleton<IPostConfigureOptions<ApiKeyAuthenticationOptions>, ApiKeyAuthenticationPostConfigureOptions>();
        builder.Services.AddTransient<IApiKeyAuthenticationService, TAuthService>();
        return builder.AddScheme<ApiKeyAuthenticationOptions, ApiKeyAuthenticationHandler>(authenticationScheme, configureOptions);
    }
}
