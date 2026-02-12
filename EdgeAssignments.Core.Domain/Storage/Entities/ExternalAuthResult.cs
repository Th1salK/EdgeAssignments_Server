namespace EdgeAssignments.Core.Domain.Storage.Entities;

public class ExternalAuthResult
{
    
    public string Provider { get; set; } = string.Empty;
    public string ProviderUserId { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public bool EmailVerified { get; set; }
    public bool IsValid { get; set; }
    public string? ErrorMessage { get; set; }
}