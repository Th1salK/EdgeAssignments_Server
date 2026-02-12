using System.ComponentModel.DataAnnotations;

namespace EdgeAssignments.API.Dtos.Post;

public class GoogleAuthDto
{
    [Required(ErrorMessage = "ID token is required")]
    public string IdToken { get; set; } = string.Empty;
}