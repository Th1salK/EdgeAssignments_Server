using EdgeAssignments.Core.Domain.Storage.Entities;
using System.Linq.Expressions;

namespace EdgeAssignments.Core.Domain.Common.Repositories;

public interface IBaseRepository<T> where T : BaseEntity
{
    Task<List<T>> TextSearchAsync(string searchText, List<string> fieldsList);
    Task<T> AddAsync(T obj);
    Task<T> AddWithIdAsync(T obj);
    Task DeleteAsync(Guid id);
    Task DeleteAsync(Expression<Func<T, bool>> predicate);
    Task<List<T>> GetAllAsync(string? tenant = null);
    Task<T> GetByIdAsync(Guid id);
    Task<List<T>> GetByIdsAsync(List<Guid> id, string? tenant = null);
    Task PutAllAsync(IEnumerable<T> entities);
    Task<List<T>> SearchAsync(Expression<Func<T, bool>> predicate, string? tenant = null);
    Task<T> UpdateAsync(T obj, Expression<Func<T, bool>>? predicate = null);
    Task AddAllAsync(IEnumerable<T> entities);
    Task UpdateAllAsync(IEnumerable<T> entities);
    Task<int> CountAsync();
}
