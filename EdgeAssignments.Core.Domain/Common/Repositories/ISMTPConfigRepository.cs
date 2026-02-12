using EdgeAssignments.Core.Domain.Storage.Entities;

namespace EdgeAssignments.Core.Domain.Common.Repositories;

public interface ISMTPConfigRepository 
{
    /// Get the active SMTP configuration
    /// Returns the first ACTIVE configuration found
    /// Active SMTP config or null if none found
    Task<SMTPConfig?> GetActiveConfigAsync();
    
    /// Get SMTP configuration by ID
    Task<SMTPConfig?> GetByIdAsync(string id);
    
    /// Check if any active SMTP configuration exists
    Task<bool> HasActiveConfigAsync();
}