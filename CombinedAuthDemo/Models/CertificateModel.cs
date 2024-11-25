using System.ComponentModel.DataAnnotations;

namespace CombinedAuthDemo.Models;

internal sealed class CertificateModel
{
    [Required]
    public required string Issuer { get; set; }

    [Required]
    public required string Subject { get; set; }

    [Required]
    public required string Thumbprint { get; set; }
}