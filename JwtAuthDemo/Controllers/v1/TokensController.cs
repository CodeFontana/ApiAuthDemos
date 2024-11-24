using JwtAuthDemo.Interfaces;
using JwtAuthDemo.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace JwtAuthDemo.Controllers.v1;

[ApiController]
[Route("api/v{version:apiVersion}/[controller]")]
[EnableRateLimiting("fixed")]
public class TokensController : ControllerBase
{
    private readonly IConfiguration _config;
    private readonly ITokenService _tokenService;

    public TokensController(IConfiguration configuration, ITokenService tokenService)
    {
        _config = configuration;
        _tokenService = tokenService;
    }

    [HttpPost]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [AllowAnonymous]
    public ActionResult<string> GetToken([FromBody] LoginUserModel loginUser)
    {
        List<LoginUserModel> authorizedUsers = _config.GetSection("ApiUsers").Get<List<LoginUserModel>>()
            ?? throw new InvalidOperationException("ApiUsers is missing in appsettings.json");

        LoginUserModel? foundUser = authorizedUsers
            .Where(x => x.Username.Equals(loginUser.Username)
                && x.Password.Equals(loginUser.Password))
            .FirstOrDefault();

        if (foundUser is null)
        {
            return Unauthorized("Invalid username or password");
        }

        string token = _tokenService.CreateTokenAsync(foundUser.Username);
        return Ok(token);
    }
}
