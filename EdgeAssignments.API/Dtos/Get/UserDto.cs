namespace EdgeAssignments.API.Dtos.Get;

public class UserDto
{
    public Guid Id { get; set; } = Guid.Empty;
    public string Name { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public string Role { get; set; } = string.Empty;
    public string Status { get; set; } = string.Empty;
    public DateTime? LastLogin { get; set; }
    public string? LanguagePreference { get; set; }
    public string? NotificationPreference { get; set; }
    public bool ProfileCompleted { get; set; }
}