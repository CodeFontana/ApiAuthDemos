namespace JwtAuthDemo.Interfaces;

public interface ITokenService
{
    string CreateTokenAsync(string username);
}