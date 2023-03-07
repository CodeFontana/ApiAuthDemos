using JwtAuthDemo.Interfaces;
using JwtAuthDemo.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace WebApi.Controllers.v1;

[ApiController]
[Route("api/v{version:apiVersion}/[controller]")]
public class TokensController : ControllerBase
{
    private readonly IConfiguration _config;
    private readonly ITokenService _tokenService;

    public TokensController(IConfiguration configuration, ITokenService tokenService)
    {
        _config = configuration;
        _tokenService = tokenService;
    }

    // POST api/v1/Tokens
    [HttpPost]
    [AllowAnonymous]
    public ActionResult<string> GetToken([FromBody] LoginUserModel loginUser)
    {
        List<LoginUserModel> authorizedUsers = _config.GetSection("ApiUsers").Get<List<LoginUserModel>>();
        LoginUserModel foundUser = authorizedUsers
            .Where(x => x.Username.ToLower().Equals(loginUser.Username.ToLower()))
            .Where(x => x.Password.ToLower().Equals(loginUser.Password.ToLower()))
            .FirstOrDefault();

        if (foundUser is null)
        {
            return Unauthorized("Invalid username or password");
        }

        string token = _tokenService.CreateTokenAsync(foundUser.Username);
        return Ok(token);
    }
}
