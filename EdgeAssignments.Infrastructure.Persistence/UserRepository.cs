

using EdgeAssignments.Core.Domain.Common.Repositories;
using EdgeAssignments.Core.Domain.Storage.Entities;
using EdgeAssignments.Core.Domain.Storage.Configs;
using Microsoft.AspNetCore.Http;
using MongoDB.Driver;


namespace EdgeAssignments.Infrastructure.Persistence;

public class UserRepository : MongoRepository<User>, IUserRepository
{
    public UserRepository(ApplicationSettings settings, IHttpContextAccessor httpContextAccessor)
    :base(settings, httpContextAccessor)
    {
        var indexKeys = Builders<User>.IndexKeys.Ascending(u => u.Email);
        var indexOptions = new CreateIndexOptions { Unique = true };
        var indexModel = new CreateIndexModel<User>(indexKeys, indexOptions);
        Collection.Indexes.CreateOneAsync(indexModel).GetAwaiter().GetResult();
    }

    public async Task<User?> GetByEmailAsync(string email)
    {
        var user = await SearchAsync(u => u.Email.ToLower() == email.ToLower() && !u.IsDeleted);
        return user.FirstOrDefault();
    }
    
    public async Task<User?> GetByEmailVerificationTokenAsync(string token)
    {
        var user = await SearchAsync(u => u.EmailVerificationToken == token && !u.IsDeleted);
        return user.FirstOrDefault();
    }
    
    public async Task<User?> GetByPasswordResetTokenAsync(string token)
    {
        var user = await SearchAsync(u => u.PasswordResetToken == token && !u.IsDeleted);
        return user.FirstOrDefault();
    }
    
    public async Task<User?> GetByRefreshTokenAsync(string refreshToken)
    {
        var user = await SearchAsync(u => u.RefreshToken == refreshToken && !u.IsDeleted);
        return user.FirstOrDefault();
    }
    
    public async Task<bool> EmailExistsAsync(string email)
    {
        var user = await SearchAsync(u => u.Email.ToLower() == email.ToLower() && !u.IsDeleted);
        return user.Any();
    }
}