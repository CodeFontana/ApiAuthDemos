using System.Security.Cryptography.X509Certificates;
using CertAuthDemo.Interfaces;

namespace CertAuthDemo.Services;

public sealed class CertificateValidationService : ICertificateValidationService
{
    public bool ValidateCertificate(X509Certificate2 clientCertificate)
    {
        string[] allowedThumbprints =
        [
            "905CEE7AAAB00674ADBBFCD8CE13A6A7179B9E36"
        ];

        if (allowedThumbprints.Contains(clientCertificate.Thumbprint))
        {
            return true;
        }

        return false;
    }
}
