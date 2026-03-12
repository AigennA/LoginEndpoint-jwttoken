using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using AuthApiDemo.Services;
using Microsoft.Extensions.Configuration;

namespace AuthApiDemo.Tests;

// Enhetstester för TokenService — kopplar till moment 3-4 (xUnit, Arrange-Act-Assert)
public class TokenServiceTests
{
    // Hjälpmetod: skapar en TokenService med en realistisk testkonfiguration
    private static TokenService CreateTokenService()
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Jwt:Key"] = "TestNyckelSomArMinstTrettiоTvaTecken12345",
                ["Jwt:Issuer"] = "https://localhost:7001",
                ["Jwt:Audience"] = "https://localhost:3000",
                ["Jwt:ExpirationMinutes"] = "60"
            })
            .Build();

        return new TokenService(config);
    }

    private static UserDto CreateTestUser() =>
        new(1, "test@example.com", "Test Testsson", "User");

    // --- GenerateAccessToken-tester ---

    [Fact]
    public void GenerateAccessToken_ReturnsStringWithThreeParts()
    {
        // Arrange
        var service = CreateTokenService();
        var user = CreateTestUser();

        // Act
        var token = service.GenerateAccessToken(user);

        // Assert — JWT-format är alltid header.payload.signature (tre delar separerade av '.')
        var parts = token.Split('.');
        Assert.Equal(3, parts.Length);
    }

    [Fact]
    public void GenerateAccessToken_ContainsCorrectSubClaim()
    {
        // Arrange
        var service = CreateTokenService();
        var user = CreateTestUser();

        // Act
        var token = service.GenerateAccessToken(user);

        // Assert — läs ut claims direkt ur token utan validering
        var handler = new JwtSecurityTokenHandler();
        var jwt = handler.ReadJwtToken(token);

        var sub = jwt.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Sub)?.Value;
        Assert.Equal(user.Id.ToString(), sub);
    }

    [Fact]
    public void GenerateAccessToken_ContainsCorrectRoleClaim()
    {
        // Arrange
        var service = CreateTokenService();
        var adminUser = new UserDto(2, "admin@example.com", "Admin", "Admin");

        // Act
        var token = service.GenerateAccessToken(adminUser);

        // Assert
        var handler = new JwtSecurityTokenHandler();
        var jwt = handler.ReadJwtToken(token);

        var role = jwt.Claims.FirstOrDefault(c =>
            c.Type == ClaimTypes.Role ||
            c.Type == "role")?.Value;

        Assert.Equal("Admin", role);
    }

    // --- ValidateToken-tester ---

    [Fact]
    public void ValidateToken_ReturnsClaimsPrincipalForValidToken()
    {
        // Arrange
        var service = CreateTokenService();
        var user = CreateTestUser();
        var token = service.GenerateAccessToken(user);

        // Act
        var principal = service.ValidateToken(token);

        // Assert
        Assert.NotNull(principal);
        Assert.IsType<ClaimsPrincipal>(principal);
    }

    [Fact]
    public void ValidateToken_ReturnsNullForTamperedToken()
    {
        // Arrange
        var service = CreateTokenService();
        var user = CreateTestUser();
        var token = service.GenerateAccessToken(user);

        // Manipulera signaturen — ändra sista tecken
        var tampered = token[..^5] + "XXXXX";

        // Act
        var principal = service.ValidateToken(tampered);

        // Assert
        Assert.Null(principal);
    }

    [Fact]
    public void ValidateToken_ReturnsNullForRandomString()
    {
        // Arrange
        var service = CreateTokenService();

        // Act
        var principal = service.ValidateToken("det.har.ar.inget.giltigt.token");

        // Assert
        Assert.Null(principal);
    }

    // --- GenerateRefreshToken-tester ---

    [Fact]
    public void GenerateRefreshToken_ReturnsUniqueStrings()
    {
        // Arrange
        var service = CreateTokenService();

        // Act — generera flera tokens och kontrollera att de är unika
        var tokens = Enumerable.Range(0, 10)
            .Select(_ => service.GenerateRefreshToken())
            .ToList();

        // Assert
        Assert.Equal(tokens.Count, tokens.Distinct().Count());
    }

    [Fact]
    public void GenerateRefreshToken_ReturnsNonEmptyString()
    {
        // Arrange
        var service = CreateTokenService();

        // Act
        var token = service.GenerateRefreshToken();

        // Assert — 64 bytes som Base64 ger 88 tecken
        Assert.NotNull(token);
        Assert.True(token.Length > 50);
    }
}
