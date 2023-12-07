using System.ComponentModel.DataAnnotations;

namespace CombinedAuthDemo.Models;

public class ApiKeyModel
{
    [Required]
    public string HeaderName { get; set; }

    [Required]
    public string ApiKey { get; set; }

    [Required]
    public string IssuedTo { get; set; }
}
