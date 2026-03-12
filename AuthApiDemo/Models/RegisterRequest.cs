using System.ComponentModel.DataAnnotations;

namespace AuthApiDemo.Models;

public record RegisterRequest(
    [Required(ErrorMessage = "E-post är obligatorisk")]
    [EmailAddress(ErrorMessage = "Ogiltig e-postadress")]
    string Email,

    [Required(ErrorMessage = "Namn är obligatoriskt")]
    string Name,

    [Required(ErrorMessage = "Lösenord är obligatoriskt")]
    [MinLength(6, ErrorMessage = "Lösenordet måste vara minst 6 tecken")]
    string Password
);
