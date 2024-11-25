using CombinedAuthDemo.Interfaces;
using CombinedAuthDemo.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace CombinedAuthDemo.Controllers.v1;

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
        List<LoginUserModel> authorizedUsers = _config.GetSection("ApiUsers")?.Get<List<LoginUserModel>>() ??
            throw new InvalidOperationException("ApiUsers section is missing from configuration");

        LoginUserModel? foundUser = authorizedUsers
            .Where(x => x.Username.Equals(
                loginUser.Username,
                StringComparison.InvariantCultureIgnoreCase)
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
