using System.Security.Claims;

namespace AuthApiDemo.Services;

// Interface Segregation (SOLID): kontraktet för token-hantering
public interface ITokenService
{
    // Genererar en kortlivad JWT med user-claims inbakade
    string GenerateAccessToken(UserDto user);

    // Genererar en långlivad, kryptografiskt slumpmässig refresh token
    string GenerateRefreshToken();

    // Validerar token och returnerar ClaimsPrincipal om giltig, annars null
    ClaimsPrincipal? ValidateToken(string token);
}
