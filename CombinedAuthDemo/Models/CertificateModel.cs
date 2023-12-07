using System.ComponentModel.DataAnnotations;

namespace CombinedAuthDemo.Models;

internal sealed class CertificateModel
{
    [Required]
    public string Issuer { get; set; } = string.Empty;

    [Required]
    public string Subject { get; set; } = string.Empty;

    [Required]
    public string Thumbprint { get; set; } = string.Empty;
}