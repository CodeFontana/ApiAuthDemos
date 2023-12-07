namespace CombinedAuthDemo.Interfaces;

public interface ITokenService
{
    string CreateTokenAsync(string username);
}