using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using OAuthServerDemo.Interfaces;

namespace OAuthServerDemo.Services;

public sealed class TokenService : ITokenService
{
    private readonly SymmetricSecurityKey _key;
    private readonly string _issuer;
    private readonly string _audience;
    private readonly int _accessTokenLifetimeMinutes;

    public TokenService(IConfiguration config)
    {
        string securityKey = config["OAuth:SecurityKey"]
            ?? throw new InvalidOperationException("OAuth:SecurityKey is missing from configuration");
        _key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(securityKey));
        _issuer = config["OAuth:Issuer"]
            ?? throw new InvalidOperationException("OAuth:Issuer is missing from configuration");
        _audience = config["OAuth:Audience"]
            ?? throw new InvalidOperationException("OAuth:Audience is missing from configuration");
        _accessTokenLifetimeMinutes = int.Parse(config["OAuth:AccessTokenExpiryInMinutes"]
            ?? throw new InvalidOperationException("OAuth:AccessTokenExpiryInMinutes is missing from configuration"));
    }

    public string CreateAccessToken(string clientId, IEnumerable<string> scopes)
    {
        List<Claim> claims =
        [
            new Claim(JwtRegisteredClaimNames.Sub, clientId),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim("client_id", clientId),
            new Claim(JwtRegisteredClaimNames.Iss, _issuer),
            new Claim(JwtRegisteredClaimNames.Aud, _audience),
            new Claim(JwtRegisteredClaimNames.Nbf, new DateTimeOffset(DateTime.UtcNow).ToUnixTimeSeconds().ToString()),
            new Claim(JwtRegisteredClaimNames.Exp, new DateTimeOffset(DateTime.UtcNow.AddMinutes(_accessTokenLifetimeMinutes)).ToUnixTimeSeconds().ToString()),
        ];

        foreach (string scope in scopes)
        {
            claims.Add(new Claim("scope", scope));
        }

        SigningCredentials signingCredentials = new(_key, SecurityAlgorithms.HmacSha256);
        JwtSecurityToken token = new(new JwtHeader(signingCredentials), new JwtPayload(claims));
        JwtSecurityTokenHandler tokenHandler = new();
        return tokenHandler.WriteToken(token);
    }
}
