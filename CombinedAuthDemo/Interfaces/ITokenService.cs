namespace JwtAndAPiKeyAuthDemo.Interfaces;

public interface ITokenService
{
    string CreateTokenAsync(string username);
}