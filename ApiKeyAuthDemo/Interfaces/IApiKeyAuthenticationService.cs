namespace ApiKeyAuthDemo.Interfaces;

public interface IApiKeyAuthenticationService
{
    Task<bool> IsValidAsync(string headerName, string apiKey);
}
