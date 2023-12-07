namespace CombinedAuthDemo;

public interface IApiKeyAuthenticationService
{
    Task<bool> IsValidAsync(string headerName, string apiKey);
}
