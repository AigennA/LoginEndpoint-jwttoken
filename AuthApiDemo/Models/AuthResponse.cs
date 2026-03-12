namespace AuthApiDemo.Models;

public record AuthResponse(
    bool Success,
    string? AccessToken = null,
    string? RefreshToken = null,
    int ExpiresIn = 0,
    string? Error = null
);
