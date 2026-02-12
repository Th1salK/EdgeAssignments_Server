using EdgeAssignments.Core.Domain.Storage.Entities;

namespace EdgeAssignments.Core.Domain.Common.Repositories;

public interface IAuditLogRepository : IBaseRepository<AuditLog>
{
    Task<List<AuditLog>> GetByUserIdAsync(Guid userId);
    Task<List<AuditLog>> GetByActionAsync(string action);
}