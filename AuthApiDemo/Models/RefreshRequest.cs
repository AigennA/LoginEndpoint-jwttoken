using System.ComponentModel.DataAnnotations;

namespace AuthApiDemo.Models;

public record RefreshRequest(
    [Required(ErrorMessage = "RefreshToken är obligatorisk")]
    string RefreshToken
);
