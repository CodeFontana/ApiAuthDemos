using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using JwtAuthDemo.Interfaces;
using Microsoft.IdentityModel.Tokens;

namespace JwtAuthDemo.Services;

public class TokenService : ITokenService
{
    private readonly SymmetricSecurityKey _key;
    private readonly string _jwtIssuer;
    private readonly string _jwtAudience;
    private readonly int _jwtLifetimeMinutes;

    public TokenService(IConfiguration config)
    {
        string jwtSecurityKey = config["Authentication:JwtSecurityKey"]
            ?? throw new InvalidOperationException("JwtSecurityKey is not configured");
        _key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSecurityKey));
        _jwtIssuer = config["Authentication:JwtIssuer"]
            ?? throw new InvalidOperationException("JwtIssuer is not configured");
        _jwtAudience = config["Authentication:JwtAudience"]
            ?? throw new InvalidOperationException("JwtAudience is not configured");
        _jwtLifetimeMinutes = int.Parse(config["Authentication:JwtExpiryInMinutes"]
            ?? throw new InvalidOperationException("JwtExpiryInMinutes is not configured"));
    }

    public string CreateTokenAsync(string username)
    {
        List<Claim> claims =
        [
            new Claim(ClaimTypes.Name, username),
            new Claim(JwtRegisteredClaimNames.UniqueName, username),
            new Claim(JwtRegisteredClaimNames.Iss, _jwtIssuer),
            new Claim(JwtRegisteredClaimNames.Aud, _jwtAudience),
            new Claim(JwtRegisteredClaimNames.Nbf, new DateTimeOffset(DateTime.Now).ToUnixTimeSeconds().ToString()),
            new Claim(JwtRegisteredClaimNames.Exp, new DateTimeOffset(DateTime.Now.AddMinutes(_jwtLifetimeMinutes)).ToUnixTimeSeconds().ToString())
        ];

        SigningCredentials signingCredentials = new(_key, SecurityAlgorithms.HmacSha256);
        JwtSecurityToken token = new(new JwtHeader(signingCredentials), new JwtPayload(claims));
        JwtSecurityTokenHandler tokenHandler = new();
        return tokenHandler.WriteToken(token);
    }
}
