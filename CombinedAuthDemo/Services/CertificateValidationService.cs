using System.Security.Cryptography.X509Certificates;
using CombinedAuthDemo.Interfaces;
using CombinedAuthDemo.Models;

namespace CombinedAuthDemo.Services;

internal sealed class CertificateValidationService : ICertificateValidationService
{
    private readonly IConfiguration _config;
    private readonly ILogger<CertificateValidationService> _logger;

    public CertificateValidationService(IConfiguration config, ILogger<CertificateValidationService> logger)
    {
        _config = config;
        _logger = logger;
    }

    public bool ValidateCertificate(X509Certificate2 clientCertificate)
    {
        // Log client certificate information
        _logger.LogInformation("Validate client certificate: Issuer={issuer}, Subject={subject}, Thumbprint={thumb}",
            clientCertificate.Issuer,
            clientCertificate.Subject,
            clientCertificate.Thumbprint);

        // Get list of allowed certificates from configuration
        IEnumerable<CertificateModel> allowedCerts = _config.GetSection("Certificates")?
            .Get<IEnumerable<CertificateModel>>()
            ?? throw new InvalidOperationException("Certifcates section is missing from configuration");

        // Verify if the client certificate matches one of the allowed certificates
        bool result = allowedCerts
            .Any(x =>
                x.Thumbprint.Equals(clientCertificate.Thumbprint, StringComparison.InvariantCultureIgnoreCase)
                && x.Subject.Equals(clientCertificate.Subject, StringComparison.InvariantCultureIgnoreCase)
                && x.Issuer.Equals(clientCertificate.Issuer, StringComparison.InvariantCultureIgnoreCase));

        if (result)
        {
            _logger.LogInformation("Client certificate OK: Issuer={issuer}, Subject={subject}, Thumbprint={thumb}",
                clientCertificate.Issuer,
                clientCertificate.Subject,
                clientCertificate.Thumbprint);

            return true;
        }

        _logger.LogInformation("Client certificate not allowed: Issuer={issuer}, Subject={subject}, Thumbprint={thumb}",
                clientCertificate.Issuer,
                clientCertificate.Subject,
                clientCertificate.Thumbprint);

        return false;
    }
}