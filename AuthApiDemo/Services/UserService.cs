using AuthApiDemo.Models;

namespace AuthApiDemo.Services;

// Single Responsibility (SOLID): ansvarar enbart för användarhantering
// In-memory "databas" — ersätts med EF Core + riktig databas i moment 16
public class UserService : IUserService
{
    private readonly List<User> _users = [];
    private int _nextId = 1;

    public UserService()
    {
        // Förifylld admin-användare med BCrypt-hashat lösenord
        _users.Add(new User
        {
            Id = _nextId++,
            Email = "admin@example.com",
            Name = "Admin Adminsson",
            PasswordHash = BCrypt.Net.BCrypt.HashPassword("Admin123!"),
            Role = "Admin"
        });
    }

    public Task<User?> GetByEmailAsync(string email)
    {
        var user = _users.FirstOrDefault(u =>
            string.Equals(u.Email, email, StringComparison.OrdinalIgnoreCase));
        return Task.FromResult(user);
    }

    public Task<User?> GetByIdAsync(int id)
    {
        var user = _users.FirstOrDefault(u => u.Id == id);
        return Task.FromResult(user);
    }

    public Task<User> CreateAsync(RegisterRequest request)
    {
        var user = new User
        {
            Id = _nextId++,
            Email = request.Email,
            Name = request.Name,
            PasswordHash = BCrypt.Net.BCrypt.HashPassword(request.Password),
            Role = "User"
        };
        _users.Add(user);
        return Task.FromResult(user);
    }

    public async Task<User?> ValidatePasswordAsync(string email, string password)
    {
        var user = await GetByEmailAsync(email);
        if (user is null)
            return null;

        // BCrypt.Verify är tidskonstant — skyddar mot timing-attacker
        return BCrypt.Net.BCrypt.Verify(password, user.PasswordHash) ? user : null;
    }

    public Task UpdateRefreshTokenAsync(int userId, string? refreshToken, DateTime? expiry)
    {
        var user = _users.FirstOrDefault(u => u.Id == userId);
        if (user is not null)
        {
            user.RefreshToken = refreshToken;
            user.RefreshTokenExpiry = expiry;
        }
        return Task.CompletedTask;
    }

    public Task<User?> GetByRefreshTokenAsync(string refreshToken)
    {
        var user = _users.FirstOrDefault(u => u.RefreshToken == refreshToken);
        return Task.FromResult(user);
    }
}
