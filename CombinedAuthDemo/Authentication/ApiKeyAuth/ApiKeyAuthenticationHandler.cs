using JwtAndApiKeyAuthDemo;
using JwtAndApiKeyAuthDemo.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using System.Security.Claims;
using System.Text.Encodings.Web;

namespace CombinedAuthDemo.Authentication.ApiKeyAuth;

/// <summary>
/// Constructor
/// </summary>
public class ApiKeyAuthenticationHandler : AuthenticationHandler<ApiKeyAuthenticationOptions>
{
    private readonly IConfiguration _configuration;
    private readonly IApiKeyAuthenticationService _authenticationService;

    public ApiKeyAuthenticationHandler(IOptionsMonitor<ApiKeyAuthenticationOptions> options,
                                       ILoggerFactory logger,
                                       UrlEncoder encoder,
                                       IConfiguration configuration,
                                       IApiKeyAuthenticationService authenticationService) : base(options, logger, encoder)
    {
        _configuration = configuration;
        _authenticationService = authenticationService;
    }

    /// <summary>
    /// Handles API key authentication 
    /// </summary>
    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        // Get list of API keys from configuration
        List<ApiKeyModel> apiKeys = _configuration.GetSection("ApiKeys").Get<List<ApiKeyModel>>();

        // Get first header, which matches the specification of one of our API keys
        // Hint: Our configuration supports multiple API keys, each of which could be
        //       specified with a custom header name.
        KeyValuePair<string, StringValues> apiKeyHeader = Request.Headers
            .FirstOrDefault(h => apiKeys.Select(x => x.HeaderName.ToLower()).Contains(h.Key.ToLower()));

        // Authorization header not in request?
        if (apiKeyHeader.Equals(default(KeyValuePair<string, StringValues>)))
        {
            return AuthenticateResult.Fail("Missing API key");
        }

        // Is the API key for the specified header valid?
        bool isValid = await _authenticationService.IsValidAsync(apiKeyHeader.Key, apiKeyHeader.Value);

        if (isValid == false)
        {
            return AuthenticateResult.Fail("Invalid API key");
        }

        // Extract 'IssuedTo' information, to create claim for successfully authenticated user
        ApiKeyModel apiKey = apiKeys.FirstOrDefault(x => x.HeaderName.ToLower().Equals(apiKeyHeader.Key.ToLower()));
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
