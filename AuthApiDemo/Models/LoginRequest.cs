using System.ComponentModel.DataAnnotations;

namespace AuthApiDemo.Models;

public record LoginRequest(
    [Required(ErrorMessage = "E-post är obligatorisk")]
    string Email,

    [Required(ErrorMessage = "Lösenord är obligatoriskt")]
    string Password
);
