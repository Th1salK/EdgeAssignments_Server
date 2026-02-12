namespace EdgeAssignments.Infrastructure.Persistence;
using EdgeAssignments.Core.Domain.Storage.Entities;
using EdgeAssignments.Core.Domain.Common.Repositories;
using EdgeAssignments.Core.Domain.Storage.Configs;
using Microsoft.AspNetCore.Http;

public class AuditLogRepository : MongoRepository<AuditLog>, IAuditLogRepository
{
 
    public AuditLogRepository(ApplicationSettings settings, IHttpContextAccessor httpContextAccessor)
        : base(settings, httpContextAccessor)
    {
    }

    public async Task<List<AuditLog>> GetByUserIdAsync(Guid userId)
    {
        return await SearchAsync(a => a.UserId == userId);
    }

    public async Task<List<AuditLog>> GetByActionAsync(string action)
    {
        return await SearchAsync(a => a.Action == action);
    }
}