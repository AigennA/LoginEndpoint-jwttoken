using System.Security.Claims;
using AuthApiDemo.Controllers;
using AuthApiDemo.Models;
using AuthApiDemo.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Moq;

namespace AuthApiDemo.Tests;

// Enhetstester för AuthController med Moq — kopplar till moment 3-4
public class AuthControllerTests
{
    private readonly Mock<ITokenService> _tokenServiceMock;
    private readonly Mock<IUserService> _userServiceMock;
    private readonly AuthController _controller;

    public AuthControllerTests()
    {
        _tokenServiceMock = new Mock<ITokenService>();
        _userServiceMock = new Mock<IUserService>();
        _controller = new AuthController(_tokenServiceMock.Object, _userServiceMock.Object);

        // Konfigurera standardsvar för token-generering
        _tokenServiceMock.Setup(t => t.GenerateAccessToken(It.IsAny<UserDto>()))
            .Returns("fake.access.token");
        _tokenServiceMock.Setup(t => t.GenerateRefreshToken())
            .Returns("fakeRefreshToken123");
    }

    // --- Login-tester ---

    [Fact]
    public async Task Login_WithCorrectCredentials_Returns200WithTokens()
    {
        // Arrange
        var user = new User
        {
            Id = 1, Email = "user@example.com", Name = "Test", Role = "User",
            PasswordHash = BCrypt.Net.BCrypt.HashPassword("password123")
        };

        _userServiceMock
            .Setup(s => s.ValidatePasswordAsync("user@example.com", "password123"))
            .ReturnsAsync(user);

        _userServiceMock
            .Setup(s => s.UpdateRefreshTokenAsync(It.IsAny<int>(), It.IsAny<string?>(), It.IsAny<DateTime?>()))
            .Returns(Task.CompletedTask);

        var request = new LoginRequest("user@example.com", "password123");

        // Act
        var result = await _controller.Login(request);

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result);
        Assert.Equal(200, okResult.StatusCode);

        var response = Assert.IsType<AuthResponse>(okResult.Value);
        Assert.True(response.Success);
        Assert.NotNull(response.AccessToken);
        Assert.NotNull(response.RefreshToken);
    }

    [Fact]
    public async Task Login_WithWrongCredentials_Returns401Unauthorized()
    {
        // Arrange
        _userServiceMock
            .Setup(s => s.ValidatePasswordAsync(It.IsAny<string>(), It.IsAny<string>()))
            .ReturnsAsync((User?)null);

        var request = new LoginRequest("wrong@example.com", "wrongpassword");

        // Act
        var result = await _controller.Login(request);

        // Assert
        var unauthorizedResult = Assert.IsType<UnauthorizedObjectResult>(result);
        Assert.Equal(401, unauthorizedResult.StatusCode);

        var response = Assert.IsType<AuthResponse>(unauthorizedResult.Value);
        Assert.False(response.Success);
        Assert.NotNull(response.Error);
    }

    // --- Register-tester ---

    [Fact]
    public async Task Register_WithNewEmail_Returns201Created()
    {
        // Arrange
        var newUser = new User
        {
            Id = 2, Email = "new@example.com", Name = "Ny Användare", Role = "User",
            PasswordHash = BCrypt.Net.BCrypt.HashPassword("Secret123!")
        };

        _userServiceMock
            .Setup(s => s.GetByEmailAsync("new@example.com"))
            .ReturnsAsync((User?)null);

        _userServiceMock
            .Setup(s => s.CreateAsync(It.IsAny<RegisterRequest>()))
            .ReturnsAsync(newUser);

        _userServiceMock
            .Setup(s => s.UpdateRefreshTokenAsync(It.IsAny<int>(), It.IsAny<string?>(), It.IsAny<DateTime?>()))
            .Returns(Task.CompletedTask);

        var request = new RegisterRequest("new@example.com", "Ny Användare", "Secret123!");

        // Act
        var result = await _controller.Register(request);

        // Assert
        var createdResult = Assert.IsType<CreatedAtActionResult>(result);
        Assert.Equal(201, createdResult.StatusCode);

        var response = Assert.IsType<AuthResponse>(createdResult.Value);
        Assert.True(response.Success);
        Assert.NotNull(response.AccessToken);
    }

    [Fact]
    public async Task Register_WithExistingEmail_Returns409Conflict()
    {
        // Arrange
        var existingUser = new User
        {
            Id = 1, Email = "existing@example.com", Name = "Befintlig", Role = "User",
            PasswordHash = "hash"
        };

        _userServiceMock
            .Setup(s => s.GetByEmailAsync("existing@example.com"))
            .ReturnsAsync(existingUser);

        var request = new RegisterRequest("existing@example.com", "Test", "Password123!");

        // Act
        var result = await _controller.Register(request);

        // Assert
        var conflictResult = Assert.IsType<ConflictObjectResult>(result);
        Assert.Equal(409, conflictResult.StatusCode);

        var response = Assert.IsType<AuthResponse>(conflictResult.Value);
        Assert.False(response.Success);
        Assert.NotNull(response.Error);
    }

    // --- Logout-tester ---

    [Fact]
    public async Task Logout_WithValidToken_Returns200OK()
    {
        // Arrange — simulera inloggad användare med claims
        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, "1"),
            new Claim(ClaimTypes.Email, "user@example.com")
        };
        var identity = new ClaimsIdentity(claims, "Test");
        var claimsPrincipal = new ClaimsPrincipal(identity);

        _controller.ControllerContext = new ControllerContext
        {
            HttpContext = new DefaultHttpContext { User = claimsPrincipal }
        };

        _userServiceMock
            .Setup(s => s.UpdateRefreshTokenAsync(1, null, null))
            .Returns(Task.CompletedTask);

        // Act
        var result = await _controller.Logout();

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result);
        Assert.Equal(200, okResult.StatusCode);

        // Verifiera att refresh token nollställdes
        _userServiceMock.Verify(s =>
            s.UpdateRefreshTokenAsync(1, null, null), Times.Once);
    }
}
