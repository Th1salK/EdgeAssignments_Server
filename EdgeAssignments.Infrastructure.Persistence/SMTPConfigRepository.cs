using EdgeAssignments.Core.Domain.Common.Repositories;
using EdgeAssignments.Core.Domain.Storage.Configs;
using EdgeAssignments.Core.Domain.Storage.Entities;
using Microsoft.AspNetCore.Http;
using MongoDB.Driver;

namespace EdgeAssignments.Infrastructure.Persistence;

public class SMTPConfigRepository : MongoRepository<SMTPConfig>, ISMTPConfigRepository
{
    public SMTPConfigRepository(ApplicationSettings settings, IHttpContextAccessor httpContextAccessor)
        : base(settings, httpContextAccessor)
    {
        // Create index on status field for faster queries
        CreateIndexAsync().Wait();
    }

    /// <summary>
    /// Get the active SMTP configuration
    /// Returns the first ACTIVE configuration found (sorted by lastUpdated desc)
    /// </summary>
    public async Task<SMTPConfig?> GetActiveConfigAsync()
    {
        try
        {
            var filter = Builders<SMTPConfig>.Filter.Eq(x => x.Status, SMTPConfigStatus.ACTIVE);
            var sort = Builders<SMTPConfig>.Sort.Descending(x => x.LastUpdated);

            return await Collection.Find(filter)
                .Sort(sort)
                .FirstOrDefaultAsync();
        }
        catch (Exception ex)
        {
            // Log error but don't throw - fail gracefully
            Console.WriteLine($"Error fetching active SMTP config: {ex.Message}");
            return null;
        }
    }

    /// <summary>
    /// Get SMTP configuration by ID
    /// </summary>
    public async Task<SMTPConfig?> GetByIdAsync(string id)
    {
        try
        {
            if (!Guid.TryParse(id, out var guid))
            {
                Console.WriteLine($"Invalid SMTP config ID: {id}");
                return null;
            }

            var filter = Builders<SMTPConfig>.Filter.Eq(x => x.Id, guid);
            return await Collection.Find(filter).FirstOrDefaultAsync();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error fetching SMTP config by ID {id}: {ex.Message}");
            return null;
        }
    }

    /// <summary>
    /// Check if any active SMTP configuration exists
    /// Used for health checks
    /// </summary>
    public async Task<bool> HasActiveConfigAsync()
    {
        try
        {
            var filter = Builders<SMTPConfig>.Filter.Eq(x => x.Status, SMTPConfigStatus.ACTIVE);
            var count = await Collection.CountDocumentsAsync(filter);
            return count > 0;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error checking active SMTP config: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// Create indexes for optimized queries
    /// </summary>
    private async Task CreateIndexAsync()
    {
        try
        {
            var indexKeysDefinition = Builders<SMTPConfig>.IndexKeys.Ascending(x => x.Status);
            var indexModel = new CreateIndexModel<SMTPConfig>(indexKeysDefinition);
            await Collection.Indexes.CreateOneAsync(indexModel);
        }
        catch (Exception ex)
        {
            // Index creation failure is non-fatal
            Console.WriteLine($"Warning: Failed to create SMTP config index: {ex.Message}");
        }
    }
}