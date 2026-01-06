namespace ApiKeyAuthDemo.ApiKeyAuth;

public interface IApiKeyAuthenticationService
{
    Task<bool> IsValidAsync(string headerName, string apiKey);
}
