using EdgeAssignments.Core.Domain.Storage.Entities;

namespace EdgeAssignments.API.Services.Interfaces;

/// <summary>
/// Service interface for providing SMTP configuration with caching
/// Abstracts configuration retrieval from email service
/// </summary>
public interface ISmtpConfigProvider
{
    /// <summary>
    /// Get the current active SMTP configuration
    /// Returns cached config if available, otherwise fetches from database
    /// </summary>
    /// <returns>Active SMTP config or null if unavailable</returns>
    Task<SMTPConfig?> GetConfigAsync();

    /// <summary>
    /// Force refresh of cached SMTP configuration
    /// Call this when configuration changes are detected
    /// </summary>
    Task RefreshConfigAsync();

    /// <summary>
    /// Check if SMTP service is available and configured
    /// </summary>
    /// <returns>True if SMTP is configured and ready</returns>
    Task<bool> IsConfiguredAsync();
}