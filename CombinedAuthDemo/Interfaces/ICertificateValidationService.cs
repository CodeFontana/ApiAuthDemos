using System.Security.Cryptography.X509Certificates;

namespace CombinedAuthDemo.Interfaces;

public interface ICertificateValidationService
{
    bool ValidateCertificate(X509Certificate2 clientCertificate);
}