using EdgeAssignments.API.Services.Interfaces;
using EdgeAssignments.Core.Domain.Common.Repositories;
using EdgeAssignments.Core.Domain.Storage.Entities;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
namespace EdgeAssignments.API.Services;

/// <summary>
/// SMTP Configuration Provider with in-memory caching
/// Fetches configuration from database and caches it to reduce database load
/// Supports manual refresh for configuration updates
/// </summary>
public class SmtpConfigProvider : ISmtpConfigProvider
{
    private readonly ISMTPConfigRepository _ismtpConfigRepository;
    private readonly IMemoryCache _cache;
    private readonly ILogger<SmtpConfigProvider> _logger;
    private const string CACHE_KEY = "SMTP_CONFIG";
    private const int CACHE_DURATION_MINUTES = 15; // Cache config for 15 minutes

    public SmtpConfigProvider(
        ISMTPConfigRepository ismtpConfigRepository,
        IMemoryCache cache,
        ILogger<SmtpConfigProvider> logger)
    {
        _ismtpConfigRepository = ismtpConfigRepository;
        _cache = cache;
        _logger = logger;
    }

    /// <summary>
    /// Get SMTP configuration with caching
    /// First checks memory cache, then falls back to database
    /// </summary>
    public async Task<SMTPConfig?> GetConfigAsync()
    {
        try
        {
            // Step 1: Try to get from cache
            if (_cache.TryGetValue(CACHE_KEY, out SMTPConfig? cachedConfig))
            {
                _logger.LogDebug("SMTP configuration loaded from cache");
                return cachedConfig;
            }

            // Step 2: Cache miss - fetch from database
            _logger.LogInformation("SMTP configuration cache miss - fetching from database");
            var config = await _ismtpConfigRepository.GetActiveConfigAsync();

            if (config != null)
            {
                // Step 3: Store in cache for future requests
                var cacheOptions = new MemoryCacheEntryOptions
                {
                    AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(CACHE_DURATION_MINUTES),
                    Priority = CacheItemPriority.High // Keep SMTP config in cache
                };

                _cache.Set(CACHE_KEY, config, cacheOptions);
                _logger.LogInformation("SMTP configuration cached successfully (Server: {Server}, Port: {Port})",
                    config.Server, config.Port);

                return config;
            }
            else
            {
                _logger.LogWarning("No active SMTP configuration found in database");
                return null;
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving SMTP configuration");
            return null; // Fail gracefully
        }
    }

    /// <summary>
    /// Force refresh of SMTP configuration
    /// Clears cache and fetches latest config from database
    /// Call this when configuration is updated by Member 4
    /// </summary>
    public async Task RefreshConfigAsync()
    {
        try
        {
            _logger.LogInformation("Refreshing SMTP configuration...");
            
            // Remove from cache
            _cache.Remove(CACHE_KEY);
            
            // Fetch fresh config
            var config = await GetConfigAsync();
            
            if (config != null)
            {
                _logger.LogInformation("SMTP configuration refreshed successfully");
            }
            else
            {
                _logger.LogWarning("SMTP configuration refresh completed but no active config found");
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error refreshing SMTP configuration");
        }
    }

    /// <summary>
    /// Check if SMTP service is configured and available
    /// Used for health checks and validation
    /// </summary>
    public async Task<bool> IsConfiguredAsync()
    {
        try
        {
            var config = await GetConfigAsync();
            
            // Validate that all required fields are present
            if (config == null)
            {
                _logger.LogWarning("SMTP not configured: No configuration found");
                return false;
            }

            if (string.IsNullOrWhiteSpace(config.Server))
            {
                _logger.LogWarning("SMTP not configured: Server is empty");
                return false;
            }

            if (string.IsNullOrWhiteSpace(config.Username))
            {
                _logger.LogWarning("SMTP not configured: Username is empty");
                return false;
            }

            if (string.IsNullOrWhiteSpace(config.Password))
            {
                _logger.LogWarning("SMTP not configured: Password is empty");
                return false;
            }

            if (string.IsNullOrWhiteSpace(config.FromEmail))
            {
                _logger.LogWarning("SMTP not configured: FromEmail is empty");
                return false;
            }

            _logger.LogDebug("SMTP is properly configured");
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error checking SMTP configuration");
            return false;
        }
    }
}