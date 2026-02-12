namespace EdgeAssignments.API.Services.Interfaces;

public interface IJwtService
{
    string GenerateAccessToken(Guid userId, string email, string role);
    string GenerateRefreshToken();
    string? ValidateToken(string token);
    string? GetUserIdFromToken(string token);
}