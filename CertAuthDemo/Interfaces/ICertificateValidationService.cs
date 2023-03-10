﻿using System.Security.Cryptography.X509Certificates;

public interface ICertificateValidationService
{
    bool ValidateCertificate(X509Certificate2 clientCertificate);
}