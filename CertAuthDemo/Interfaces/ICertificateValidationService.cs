using System.Security.Cryptography.X509Certificates;

namespace CertAuthDemo.Interfaces;

public interface ICertificateValidationService
{
    bool ValidateCertificate(X509Certificate2 clientCertificate);
}