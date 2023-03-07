using ApiKeyAuthDemo.Interfaces;
using ApiKeyAuthDemo.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using System.Security.Claims;
using System.Text.Encodings.Web;

namespace ApiKeyAuthDemo.ApiKeyAuth;

public class ApiKeyAuthenticationHandler : AuthenticationHandler<ApiKeyAuthenticationOptions>
{
    private const string ApiKeySchemeName = ApiKeyAuthenticationDefaults.AuthenticationScheme;
    private readonly IConfiguration _config;
    private readonly IApiKeyAuthenticationService _authenticationService;

    public ApiKeyAuthenticationHandler(IOptionsMonitor<ApiKeyAuthenticationOptions> options,
                                       ILoggerFactory logger,
                                       UrlEncoder encoder,
                                       ISystemClock clock,
                                       IConfiguration configuration,
                                       IApiKeyAuthenticationService authenticationService) : base(options, logger, encoder, clock)
    {
        _config = configuration;
        _authenticationService = authenticationService;
    }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        List<ApiKeyModel> apiKeys = _config.GetSection("ApiKeys").Get<List<ApiKeyModel>>();

        KeyValuePair<string, StringValues> apiKeyHeader = Request.Headers
            .FirstOrDefault(h => apiKeys.Select(
                x => x.HeaderName.ToLower()).Contains(h.Key.ToLower()));

        if (apiKeyHeader.Equals(default(KeyValuePair<string, StringValues>)))
        {
            return AuthenticateResult.Fail("Missing API key");
        }

        bool isValid = await _authenticationService.IsValidAsync(apiKeyHeader.Key, apiKeyHeader.Value);

        if (isValid == false)
        {
            return AuthenticateResult.Fail("Invalid API key");
        }

        ApiKeyModel apiKey = apiKeys.FirstOrDefault(x => x.HeaderName.ToLower().Equals(apiKeyHeader.Key.ToLower()));
        Claim[] claims = new[] { new Claim(ClaimTypes.Name, apiKey.IssuedTo) };
        ClaimsIdentity identity = new(claims, Scheme.Name);
        ClaimsPrincipal principal = new(identity);
        AuthenticationTicket ticket = new(principal, Scheme.Name);
        return AuthenticateResult.Success(ticket);
    }

    protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        await base.HandleChallengeAsync(properties);
    }
}
