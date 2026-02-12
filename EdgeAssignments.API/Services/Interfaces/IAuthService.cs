using EdgeAssignments.API.Dtos.Get;
using EdgeAssignments.API.Dtos.Post;
using EdgeAssignments.Core.Domain.Storage.Entities;

namespace EdgeAssignments.API.Services.Interfaces;

public interface IAuthService
{
    Task<MessageResponseDto> RegisterAsync(RegisterDto registerDto, string? ipAddress, string? userAgent);
    Task<MessageResponseDto> VerifyEmailAsync(string token, string? ipAddress, string? userAgent);
    Task<AuthResponseDto> LoginAsync(LoginDto loginDto, string? ipAddress, string? userAgent);
    Task<MessageResponseDto> LogoutAsync(Guid userId, string? ipAddress, string? userAgent);
    Task<AuthResponseDto> RefreshTokenAsync(string refreshToken, string? ipAddress, string? userAgent);
    Task<UserDto> GetUserProfileAsync(Guid userId);
    Task<MessageResponseDto> ForgotPasswordAsync(ForgotPasswordDto forgotPasswordDto, string? ipAddress, string? userAgent);
    Task<MessageResponseDto> ResetPasswordAsync(ResetPasswordDto resetPasswordDto, string? ipAddress, string? userAgent);
    Task<AuthResponseDto> ExternalLoginAsync(ExternalAuthResult authResult, string? ipAddress, string? userAgent);
}