using System.ComponentModel.DataAnnotations;

namespace OAuthServerDemo.Models;

public sealed class OAuthClientModel
{
    [Required]
    public required string ClientId { get; set; }

    [Required]
    public required string ClientSecret { get; set; }

    [Required]
    public required List<string> AllowedScopes { get; set; }
}
