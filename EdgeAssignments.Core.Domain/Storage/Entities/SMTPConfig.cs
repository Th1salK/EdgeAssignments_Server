namespace EdgeAssignments.Core.Domain.Storage.Entities;
using MongoDB.Bson.Serialization.Attributes;

public class SMTPConfig : BaseEntity
{
    [BsonElement("server")]
    public string Server { get; set; } = string.Empty;
    
    [BsonElement("port")]
    public int Port { get; set; } = 587;
    
    [BsonElement("encryptionType")]
    public string Encryption { get; set; } = EncryptionType.TLS;
    
    [BsonElement("username")]
    public string Username { get; set; } = string.Empty;
    
    [BsonElement("password")]
    public string Password { get; set; } = string.Empty;
    
    [BsonElement("fromEmail")]
    public string FromEmail { get; set; } = string.Empty;
    
    [BsonElement("status")]
    public string Status { get; set; } = SMTPConfigStatus.ACTIVE;
    
    [BsonElement("maxEmailsPerHour")]
    public int MaxEmailsPerHour { get; set; } = 0;
}


/// SMTP Configuration Status Constants
public static class SMTPConfigStatus
{
    public const string ACTIVE = "ACTIVE";
    public const string INACTIVE = "INACTIVE";
}

/// Encryption Type Constants
public static class EncryptionType
{
    public const string TLS = "TLS";      
    public const string SSL = "SSL";      
    public const string NONE = "None";    
}