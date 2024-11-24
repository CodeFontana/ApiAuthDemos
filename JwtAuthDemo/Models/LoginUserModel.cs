using System.ComponentModel.DataAnnotations;

namespace JwtAuthDemo.Models;

public sealed class LoginUserModel
{
    [Required]
    public required string Username { get; set; }

    [Required]
    public required string Password { get; set; }
}
