namespace AuthApiDemo.Services;

// DTO för att föra över användardata till TokenService utan att exponera PasswordHash
public record UserDto(
    int Id,
    string Email,
    string Name,
    string Role
);
