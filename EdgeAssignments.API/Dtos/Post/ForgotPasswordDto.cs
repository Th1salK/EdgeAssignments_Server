using System.ComponentModel.DataAnnotations;

namespace EdgeAssignments.API.Dtos.Post;

public class ForgotPasswordDto
{
    [Required(ErrorMessage = "Email is required")]
    [EmailAddress(ErrorMessage = "Invalid email format")]
    public string Email { get; set; } = string.Empty;
}