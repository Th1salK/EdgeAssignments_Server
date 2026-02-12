namespace EdgeAssignments.Core.Domain.Storage.Entities;

using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

public class AuditLog : BaseEntity
{
    public string Action { get; set; } = string.Empty;
    
    [BsonRepresentation(BsonType.String)]
    public Guid? UserId { get; set; }
    
    public string? UserEmail { get; set; }
    public string? IpAddress { get; set; }
    public string? UserAgent { get; set; }
    public string? Details { get; set; }
    public string Status { get; set; } = string.Empty;
    public string? ErrorMessage { get; set; }
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    
}

public static class AuditAction
{
    public const string USER_REGISTERED = "USER_REGISTERED";
    public const string EMAIL_VERIFIED = "EMAIL_VERIFIED";
    public const string USER_LOGIN = "USER_LOGIN";
    public const string LOGIN_FAILED = "LOGIN_FAILED";
    public const string USER_LOGOUT = "USER_LOGOUT";
    public const string TOKEN_REFRESHED = "TOKEN_REFRESHED";
    public const string PASSWORD_RESET_REQUESTED = "PASSWORD_RESET_REQUESTED";
    public const string PASSWORD_RESET_COMPLETED = "PASSWORD_RESET_COMPLETED";
    public const string ACCOUNT_LOCKED = "ACCOUNT_LOCKED";
}

public static class AuditStatus
{
    public const string SUCCESS = "SUCCESS";
    public const string FAILURE = "FAILURE";
    public const string ERROR = "ERROR";
}