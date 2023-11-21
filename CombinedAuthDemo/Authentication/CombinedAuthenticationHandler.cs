using CombinedAuthDemo.Authentication.ApiKeyAuth;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authorization;

namespace CombinedAuthDemo.Authentication;

public class CombinedAuthenticationHandler(IOptionsMonitor<AuthenticationSchemeOptions> options,
                                           ILoggerFactory logger,
                                           UrlEncoder encoder) : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        // Check for [AllowAnonymous] decorator on the endpoint
        Endpoint endpoint = Context.GetEndpoint();
        
        if (endpoint != null)
        {
            IAllowAnonymous allowAnonymous = endpoint.Metadata.GetMetadata<IAllowAnonymous>();

            if (allowAnonymous != null)
            {
                return AuthenticateResult.NoResult();
            }
        }

        // Try JWT Bearer authentication first
        AuthenticateResult jwtResult = await Context.AuthenticateAsync(JwtBearerDefaults.AuthenticationScheme);

        // If JWT authentication is successful, return the result
        if (jwtResult.Succeeded)
        {
            return jwtResult;
        }

        // If JWT is present but invalid, fail authentication
        if (jwtResult.Failure is SecurityTokenInvalidSignatureException)
        {
            return AuthenticateResult.Fail(jwtResult.Failure);
        }

        // If JWT authentication fails, try API Key authentication
        AuthenticateResult apiKeyResult = await Context.AuthenticateAsync(ApiKeyAuthenticationDefaults.AuthenticationScheme);

        // If API Key authentication is successful, return the result
        if (apiKeyResult.Succeeded)
        {
            return apiKeyResult;
        }

        // Authentication failed
        return AuthenticateResult.Fail("Not authorized");
    }
}
