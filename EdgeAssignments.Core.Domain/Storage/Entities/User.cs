using MongoDB.Bson.Serialization.Attributes;

namespace EdgeAssignments.Core.Domain.Storage.Entities;

//user entity
public class User : BaseEntity
{
    public string Name { get; set; } = string.Empty;
    
    [BsonElement("Email")]
    public string Email { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public string Role { get; set; } = UserRole.EXTERNAL_USER;
    public string Status { get; set; } = UserStatus.INACTIVE;
    public DateTime? LastLogin { get; set; }
    public string? LanguagePreference { get; set; }
    public string? NotificationPreference { get; set; }
    public bool ProfileCompleted { get; set; } = false;
    public bool IsDeleted { get; set; } = false;
    public string? EmailVerificationToken { get; set; }
    public DateTime? EmailVerificationTokenExpiry { get; set; }
    public string? PasswordResetToken { get; set; }
    public DateTime? PasswordResetTokenExpiry { get; set; }
    public string? RefreshToken { get; set; }
    public DateTime? RefreshTokenExpiry { get; set; }
    public int FailedLoginAttempts { get; set; } = 0;
    public DateTime? LastFailedLogin { get; set; }
    public DateTime? LockedUntil { get; set; }
    public List<ExternalLoginInfo> ExternalLogins { get; set; } = new();
    
}

public class ExternalLoginInfo
{
    public string Provider { get; set; } = string.Empty;
    public string ProviderUserId { get; set; } = string.Empty;
    public DateTime LinkedAt { get; set; } = DateTime.UtcNow;
    
}

public static class UserRole
{
    public const string ADMIN = "ADMIN";
    public const string MANAGER = "MANAGER";
    public const string EXTERNAL_USER = "EXTERNAL_USER";
}

public static class UserStatus
{
    public const string ACTIVE = "ACTIVE";
    public const string INACTIVE = "INACTIVE";
    public const string LOCKED = "LOCKED";
}