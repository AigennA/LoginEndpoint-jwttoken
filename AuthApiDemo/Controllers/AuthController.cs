using System.Security.Claims;
using AuthApiDemo.Models;
using AuthApiDemo.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AuthApiDemo.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly ITokenService _tokenService;
    private readonly IUserService _userService;

    // Båda services injiceras via DI — kopplar till moment 5-6
    public AuthController(ITokenService tokenService, IUserService userService)
    {
        _tokenService = tokenService;
        _userService = userService;
    }

    /// <summary>
    /// Registrerar en ny användare.
    /// Returnerar 409 Conflict om e-postadressen redan finns.
    /// </summary>
    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterRequest request)
    {
        var existing = await _userService.GetByEmailAsync(request.Email);
        if (existing is not null)
            return Conflict(new AuthResponse(false, Error: "E-postadressen är redan registrerad."));

        var user = await _userService.CreateAsync(request);
        var userDto = new UserDto(user.Id, user.Email, user.Name, user.Role);

        var accessToken = _tokenService.GenerateAccessToken(userDto);
        var refreshToken = _tokenService.GenerateRefreshToken();

        await _userService.UpdateRefreshTokenAsync(
            user.Id, refreshToken, DateTime.UtcNow.AddDays(7));

        return CreatedAtAction(nameof(Me), new AuthResponse(
            Success: true,
            AccessToken: accessToken,
            RefreshToken: refreshToken,
            ExpiresIn: 3600
        ));
    }

    /// <summary>
    /// Loggar in en befintlig användare.
    /// Returnerar 401 Unauthorized vid felaktiga credentials.
    /// </summary>
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        var user = await _userService.ValidatePasswordAsync(request.Email, request.Password);
        if (user is null)
            return Unauthorized(new AuthResponse(false, Error: "Felaktigt e-post eller lösenord."));

        var userDto = new UserDto(user.Id, user.Email, user.Name, user.Role);
        var accessToken = _tokenService.GenerateAccessToken(userDto);
        var refreshToken = _tokenService.GenerateRefreshToken();

        await _userService.UpdateRefreshTokenAsync(
            user.Id, refreshToken, DateTime.UtcNow.AddDays(7));

        return Ok(new AuthResponse(
            Success: true,
            AccessToken: accessToken,
            RefreshToken: refreshToken,
            ExpiresIn: 3600
        ));
    }

    /// <summary>
    /// Förnyar access token via refresh token (token rotation).
    /// Den gamla refresh token invalideras och en ny utfärdas.
    /// </summary>
    [HttpPost("refresh")]
    public async Task<IActionResult> Refresh([FromBody] RefreshRequest request)
    {
        var user = await _userService.GetByRefreshTokenAsync(request.RefreshToken);
        if (user is null)
            return Unauthorized(new AuthResponse(false, Error: "Ogiltig refresh token."));

        if (user.RefreshTokenExpiry is null || user.RefreshTokenExpiry < DateTime.UtcNow)
            return Unauthorized(new AuthResponse(false, Error: "Refresh token har löpt ut."));

        // Token rotation: generera helt nya tokens
        var userDto = new UserDto(user.Id, user.Email, user.Name, user.Role);
        var newAccessToken = _tokenService.GenerateAccessToken(userDto);
        var newRefreshToken = _tokenService.GenerateRefreshToken();

        await _userService.UpdateRefreshTokenAsync(
            user.Id, newRefreshToken, DateTime.UtcNow.AddDays(7));

        return Ok(new AuthResponse(
            Success: true,
            AccessToken: newAccessToken,
            RefreshToken: newRefreshToken,
            ExpiresIn: 3600
        ));
    }

    /// <summary>
    /// Loggar ut inloggad användare genom att invalidera refresh token.
    /// Kräver giltig JWT i Authorization-headern.
    /// </summary>
    [HttpPost("logout")]
    [Authorize]
    public async Task<IActionResult> Logout()
    {
        var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value
            ?? User.FindFirst("sub")?.Value;

        if (userIdClaim is null || !int.TryParse(userIdClaim, out int userId))
            return BadRequest(new { message = "Ogiltigt token." });

        await _userService.UpdateRefreshTokenAsync(userId, null, null);

        return Ok(new { message = "Du är nu utloggad." });
    }

    /// <summary>
    /// Returnerar profil-information för inloggad användare.
    /// Kräver giltig JWT i Authorization-headern.
    /// </summary>
    [HttpGet("me")]
    [Authorize]
    public IActionResult Me()
    {
        var id = User.FindFirst(ClaimTypes.NameIdentifier)?.Value
            ?? User.FindFirst("sub")?.Value;
        var email = User.FindFirst(ClaimTypes.Email)?.Value;
        var name = User.FindFirst(ClaimTypes.Name)?.Value;
        var role = User.FindFirst(ClaimTypes.Role)?.Value;

        return Ok(new
        {
            Id = id,
            Email = email,
            Name = name,
            Role = role
        });
    }
}
