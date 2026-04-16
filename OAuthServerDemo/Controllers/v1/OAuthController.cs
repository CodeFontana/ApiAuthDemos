using System.Net.Mime;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using OAuthServerDemo.Interfaces;
using OAuthServerDemo.Models;

namespace OAuthServerDemo.Controllers.v1;

[ApiController]
[Route("api/v1/[controller]")]
[EnableRateLimiting("fixed")]
public class OAuthController : ControllerBase
{
    private readonly IConfiguration _config;
    private readonly ITokenService _tokenService;

    public OAuthController(IConfiguration configuration, ITokenService tokenService)
    {
        _config = configuration;
        _tokenService = tokenService;
    }

    [HttpPost("token")]
    [AllowAnonymous]
    [Consumes(MediaTypeNames.Application.FormUrlEncoded)]
    [ProducesResponseType(typeof(OAuthTokenResponseModel), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(OAuthErrorResponseModel), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(OAuthErrorResponseModel), StatusCodes.Status401Unauthorized)]
    public ActionResult Token(
        [FromForm(Name = "grant_type")] string grantType,
        [FromForm(Name = "client_id")] string clientId,
        [FromForm(Name = "client_secret")] string clientSecret,
        [FromForm(Name = "scope")] string? scope,
        [FromForm(Name = "audience")] string? audience)
    {
        if (!string.Equals(grantType, "client_credentials", StringComparison.OrdinalIgnoreCase))
        {
            return BadRequest(new OAuthErrorResponseModel
            {
                Error = "unsupported_grant_type",
                ErrorDescription = "Only 'client_credentials' grant type is supported"
            });
        }

        List<OAuthClientModel> registeredClients = _config.GetSection("OAuthClients").Get<List<OAuthClientModel>>()
            ?? throw new InvalidOperationException("OAuthClients section is missing from configuration");

        OAuthClientModel? matchedClient = registeredClients
            .Where(c => c.ClientId.Equals(clientId, StringComparison.Ordinal)
                && c.ClientSecret.Equals(clientSecret, StringComparison.Ordinal))
            .FirstOrDefault();

        if (matchedClient is null)
        {
            return Unauthorized(new OAuthErrorResponseModel
            {
                Error = "invalid_client",
                ErrorDescription = "Client authentication failed"
            });
        }

        string configuredAudience = _config["OAuth:Audience"]
            ?? throw new InvalidOperationException("OAuth:Audience is missing from configuration");

        if (audience is not null && !string.Equals(audience, configuredAudience, StringComparison.OrdinalIgnoreCase))
        {
            return BadRequest(new OAuthErrorResponseModel
            {
                Error = "invalid_target",
                ErrorDescription = $"The requested audience '{audience}' is not valid"
            });
        }

        List<string> requestedScopes = string.IsNullOrWhiteSpace(scope)
            ? matchedClient.AllowedScopes
            : scope.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();

        List<string> invalidScopes = requestedScopes
            .Where(s => !matchedClient.AllowedScopes.Contains(s, StringComparer.OrdinalIgnoreCase))
            .ToList();

        if (invalidScopes.Count > 0)
        {
            return BadRequest(new OAuthErrorResponseModel
            {
                Error = "invalid_scope",
                ErrorDescription = $"The requested scope(s) '{string.Join(" ", invalidScopes)}' are not allowed for this client"
            });
        }

        int expiresInSeconds = int.Parse(_config["OAuth:AccessTokenExpiryInMinutes"]
            ?? throw new InvalidOperationException("OAuth:AccessTokenExpiryInMinutes is missing from configuration")) * 60;

        string accessToken = _tokenService.CreateAccessToken(clientId, requestedScopes);

        OAuthTokenResponseModel tokenResponse = new()
        {
            AccessToken = accessToken,
            TokenType = "Bearer",
            ExpiresIn = expiresInSeconds,
            Scope = string.Join(' ', requestedScopes)
        };

        return Ok(tokenResponse);
    }
}
