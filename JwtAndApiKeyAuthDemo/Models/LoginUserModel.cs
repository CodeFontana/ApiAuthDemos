using System.ComponentModel.DataAnnotations;

namespace JwtAndApiKeyAuthDemo.Models;

public class LoginUserModel
{
    [Required]
    public string Username { get; set; }

    [Required] 
    public string Password { get; set; }
}
