using System.ComponentModel.DataAnnotations;

namespace EdgeAssignments.API.Dtos.Post;

public class RefreshTokenDto
{
    [Required(ErrorMessage = "Refresh token is required")]
    public string RefreshToken { get; set; } = string.Empty;
}