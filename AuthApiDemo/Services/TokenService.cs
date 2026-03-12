using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace AuthApiDemo.Services;

public class TokenService : ITokenService
{
    private readonly IConfiguration _config;

    // IConfiguration injiceras av DI-containern — kopplar till moment 5-6
    public TokenService(IConfiguration config)
    {
        _config = config;
    }

    public string GenerateAccessToken(UserDto user)
    {
        var key = GetSigningKey();
        int expMinutes = int.Parse(_config["Jwt:ExpirationMinutes"] ?? "60");

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
            new(JwtRegisteredClaimNames.Email, user.Email),
            new(ClaimTypes.Name, user.Name),
            new(ClaimTypes.Role, user.Role),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };

        var descriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.AddMinutes(expMinutes),
            Issuer = _config["Jwt:Issuer"],
            Audience = _config["Jwt:Audience"],
            SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256)
        };

        var handler = new JwtSecurityTokenHandler();
        return handler.WriteToken(handler.CreateToken(descriptor));
    }

    public string GenerateRefreshToken()
    {
        // RandomNumberGenerator är kryptografiskt säker — INTE Random.Shared
        var bytes = new byte[64];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(bytes);
        return Convert.ToBase64String(bytes);
    }

    public ClaimsPrincipal? ValidateToken(string token)
    {
        var handler = new JwtSecurityTokenHandler();

        var validationParams = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = GetSigningKey(),
            ValidateIssuer = true,
            ValidIssuer = _config["Jwt:Issuer"],
            ValidateAudience = true,
            ValidAudience = _config["Jwt:Audience"],
            ValidateLifetime = true,
            ClockSkew = TimeSpan.Zero
        };

        try
        {
            var principal = handler.ValidateToken(token, validationParams, out _);
            return principal;
        }
        catch (Exception ex) when (ex is SecurityTokenException or ArgumentException)
        {
            return null;
        }
    }

    // DRY-principen: signeringsnyckeln skapas på ett ställe
    private SymmetricSecurityKey GetSigningKey()
    {
        var keyStr = _config["Jwt:Key"]
            ?? throw new InvalidOperationException("JWT-nyckel saknas! Kontrollera Jwt:Key i appsettings.");
        return new SymmetricSecurityKey(Encoding.UTF8.GetBytes(keyStr));
    }
}
