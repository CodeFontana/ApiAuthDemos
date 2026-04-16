namespace OAuthServerDemo.Interfaces;

public interface ITokenService
{
    string CreateAccessToken(string clientId, IEnumerable<string> scopes);
}
