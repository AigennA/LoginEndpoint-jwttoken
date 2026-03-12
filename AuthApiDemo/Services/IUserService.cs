using AuthApiDemo.Models;

namespace AuthApiDemo.Services;

// Interface Segregation (SOLID): kontraktet för användarhantering
public interface IUserService
{
    Task<User?> GetByEmailAsync(string email);
    Task<User?> GetByIdAsync(int id);
    Task<User> CreateAsync(RegisterRequest request);
    Task<User?> ValidatePasswordAsync(string email, string password);
    Task UpdateRefreshTokenAsync(int userId, string? refreshToken, DateTime? expiry);
    Task<User?> GetByRefreshTokenAsync(string refreshToken);
}
