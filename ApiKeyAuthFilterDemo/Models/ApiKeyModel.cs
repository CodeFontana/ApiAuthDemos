using System.ComponentModel.DataAnnotations;

namespace ApiKeyAuthFilterDemo.Models;

public sealed class ApiKeyModel
{
    [Required]
    public required string HeaderName { get; set; }

    [Required]
    public required string ApiKey { get; set; }

    [Required]
    public required string IssuedTo { get; set; }
}
