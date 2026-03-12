namespace AuthApiDemo.Models;

// Intern domänmodell — aldrig exponeras direkt i API-svar
public class User
{
    public int Id { get; set; }
    public string Email { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;

    // Aldrig klartext-lösenord — BCrypt-hash lagras här
    public string PasswordHash { get; set; } = string.Empty;
    public string Role { get; set; } = "User";

    // Refresh token-fält — null tills användaren loggar in
    public string? RefreshToken { get; set; }
    public DateTime? RefreshTokenExpiry { get; set; }
}
