using System.Security.Claims;
using System.Text.Encodings.Web;
using ApiKeyAuthDemo.Interfaces;
using ApiKeyAuthDemo.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;

namespace ApiKeyAuthDemo.ApiKeyAuth;

public class ApiKeyAuthenticationHandler : AuthenticationHandler<ApiKeyAuthenticationOptions>
{
    private readonly IConfiguration _config;
    private readonly IApiKeyAuthenticationService _authenticationService;

    public ApiKeyAuthenticationHandler(IOptionsMonitor<ApiKeyAuthenticationOptions> options,
                                       ILoggerFactory logger,
                                       UrlEncoder encoder,
                                       IConfiguration config,
                                       IApiKeyAuthenticationService authenticationService) : base(options, logger, encoder)
    {
        _config = config;
        _authenticationService = authenticationService;
    }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        List<ApiKeyModel> apiKeys = _config.GetSection("ApiKeys")?.Get<List<ApiKeyModel>>()
            ?? throw new InvalidOperationException("ApiKeys section is missing from configuration");

        KeyValuePair<string, StringValues> apiKeyHeader = Request.Headers
            .FirstOrDefault(h =>
                apiKeys.Select(x =>
                    x.HeaderName.ToLower()).Contains(h.Key.ToLower()));

        if (apiKeyHeader.Equals(default(KeyValuePair<string, StringValues>)))
        {
            return AuthenticateResult.Fail("Request missing API key header");
        }

        bool isValid = await _authenticationService.IsValidAsync(apiKeyHeader.Key, apiKeyHeader.Value!);

        if (isValid == false)
        {
            return AuthenticateResult.Fail("Invalid API key");
        }

        ApiKeyModel apiKey = apiKeys.First(x =>
            x.HeaderName.Equals(
                apiKeyHeader.Key,
                StringComparison.InvariantCultureIgnoreCase));
        Claim[] claims = [new Claim(ClaimTypes.Name, apiKey.IssuedTo)];
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
