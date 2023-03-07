using JwtAuthDemo.Interfaces;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JwtAuthDemo.Services;

public class TokenService : ITokenService
{
    private readonly SymmetricSecurityKey _key;
    private readonly string _jwtIssuer;
    private readonly string _jwtAudience;
    private readonly int _jwtLifetimeMinutes;

    public TokenService(IConfiguration config)
    {
        _key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config["Authentication:JwtSecurityKey"]));
        _jwtIssuer = config["Authentication:JwtIssuer"];
        _jwtAudience = config["Authentication:JwtAudience"];
        _jwtLifetimeMinutes = int.Parse(config["Authentication:JwtExpiryInMinutes"]);
    }

    public string CreateTokenAsync(string username)
    {
        List<Claim> claims = new()
        {
            new Claim(ClaimTypes.Name, username),
            new Claim(JwtRegisteredClaimNames.UniqueName, username),
            new Claim(JwtRegisteredClaimNames.Iss, _jwtIssuer),
            new Claim(JwtRegisteredClaimNames.Aud, _jwtAudience),
            new Claim(JwtRegisteredClaimNames.Nbf, new DateTimeOffset(DateTime.Now).ToUnixTimeSeconds().ToString()),
            new Claim(JwtRegisteredClaimNames.Exp, new DateTimeOffset(DateTime.Now.AddMinutes(_jwtLifetimeMinutes)).ToUnixTimeSeconds().ToString())
        };

        SigningCredentials signingCredentials = new(_key, SecurityAlgorithms.HmacSha256);
        JwtSecurityToken token = new(new JwtHeader(signingCredentials), new JwtPayload(claims));
        JwtSecurityTokenHandler tokenHandler = new();
        return tokenHandler.WriteToken(token);
    }
}
