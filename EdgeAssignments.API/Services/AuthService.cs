using System.Security.Cryptography;
using EdgeAssignments.API.Dtos.Get;
using EdgeAssignments.API.Dtos.Post;
using EdgeAssignments.API.Services.Interfaces;
using EdgeAssignments.Core.Domain.Common.Repositories;
using EdgeAssignments.Core.Domain.Storage.Entities;
using Microsoft.AspNetCore.Identity;
using ExternalLoginInfo = EdgeAssignments.Core.Domain.Storage.Entities.ExternalLoginInfo;

namespace EdgeAssignments.API.Services;

public class AuthService : IAuthService
{
    private readonly IUserRepository _userRepository;
    private readonly IAuditLogRepository _auditLogRepository;
    private readonly IJwtService _jwtService;
    private readonly IEmailService _emailService;
    private readonly IPasswordHasher<User> _passwordHasher;
    private readonly ILogger<AuthService> _logger;
    private readonly IConfiguration _configuration;
    
    private int MAX_FAILED_ATTEMPTS => int.TryParse(_configuration["Security:MaxFailedAttempts"], out var val) ? val : 5;
    private int LOCKOUT_DURATION_MINUTES => int.TryParse(_configuration["Security:LockoutDurationMinutes"], out var val) ? val : 30;
    private int EMAIL_TOKEN_EXPIRY_HOURS => int.TryParse(_configuration["Security:EmailTokenExpiryHours"], out var val) ? val : 24;
    private int PASSWORD_RESET_TOKEN_EXPIRY_HOURS => int.TryParse(_configuration["Security:PasswordResetTokenExpiryHours"], out var val) ? val : 24;
    private int REFRESH_TOKEN_EXPIRY_DAYS => int.TryParse(_configuration["Security:RefreshTokenExpiryDays"], out var val) ? val : 7;
    
    public AuthService(
        IUserRepository userRepository,
        IAuditLogRepository auditLogRepository,
        IJwtService jwtService,
        IEmailService emailService,
        IPasswordHasher<User> passwordHasher,
        ILogger<AuthService> logger,
        IConfiguration configuration)
    {
        _userRepository = userRepository;
        _auditLogRepository = auditLogRepository;
        _jwtService = jwtService;
        _emailService = emailService;
        _passwordHasher = passwordHasher;
        _logger = logger;
        _configuration = configuration;
    }

    // Register a new user
    public async Task<MessageResponseDto> RegisterAsync(RegisterDto dto, string? ipAddress, string? userAgent)
    {
        try
        {
            if (await _userRepository.EmailExistsAsync(dto.Email))
            {
                await LogAuditAsync(AuditAction.USER_REGISTERED, null, dto.Email,
                    AuditStatus.FAILURE, "Email already exists", ipAddress, userAgent);
                throw new InvalidOperationException("Email address is already registered");
            }

            var passwordHash = _passwordHasher.HashPassword(null!, dto.Password);
            var verificationToken = GenerateSecureToken();

            // Create user entity
            var user = new User
            {
                Name = dto.Name,
                Email = dto.Email.ToLower(),
                Password = passwordHash,
                Role = UserRole.EXTERNAL_USER,
                Status = UserStatus.INACTIVE,
                LanguagePreference = dto.LanguagePreference ?? "en",
                ProfileCompleted = false,
                EmailVerificationToken = verificationToken,
                EmailVerificationTokenExpiry = DateTime.UtcNow.AddHours(EMAIL_TOKEN_EXPIRY_HOURS),
                CreatedBy = dto.Email,
                LastUpdated = DateTime.UtcNow
            };

            var createdUser = await _userRepository.AddAsync(user);

            // Send welcome email
            _ = Task.Run(async () =>
            {
                try
                {
                    await _emailService.SendEmailVerificationAsync(createdUser.Email, createdUser.Name,
                        verificationToken);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Failed to send welcome email to {Email}", user.Email);
                }
            });
            
            await LogAuditAsync(AuditAction.USER_REGISTERED, createdUser.Id, createdUser.Email,
                AuditStatus.SUCCESS, $"User registered: {createdUser.Name}", ipAddress, userAgent);
            
            return new MessageResponseDto
            {
                Message = "Registration successful. Please check your email to verify your account.",
                Success = true
            };




        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Registration failed for email {Email}", dto.Email);
            await LogAuditAsync(AuditAction.USER_REGISTERED, null, dto.Email,
                AuditStatus.ERROR, ex.Message, ipAddress, userAgent);
            throw;
        }
        
    }

    /// Verify user email address
    public async Task<MessageResponseDto> VerifyEmailAsync(string token, string? ipAddress, string? userAgent)
    {
        try
        {
            var user = await _userRepository.GetByEmailVerificationTokenAsync(token);

            if (user == null)
            {
                await LogAuditAsync(AuditAction.EMAIL_VERIFIED, null, null,
                    AuditStatus.FAILURE, "Invalid verification token", ipAddress, userAgent);
                throw new InvalidOperationException("Invalid or expired verification token");
            }

            if (user.EmailVerificationTokenExpiry < DateTime.UtcNow)
            {
                await LogAuditAsync(AuditAction.EMAIL_VERIFIED, user.Id, user.Email,
                    AuditStatus.FAILURE, "Verification token expired", ipAddress, userAgent);
                throw new InvalidOperationException("Verification token has expired");
            }

            // Activate user account
            user.Status = UserStatus.ACTIVE;
            user.EmailVerificationToken = null;
            user.EmailVerificationTokenExpiry = null;
            user.LastUpdated = DateTime.UtcNow;
            user.UpdatedBy = user.Email;

            await _userRepository.UpdateAsync(user);

            // Send welcome email
            _ = Task.Run(async () =>
            {
                try
                {
                    await _emailService.SendWelcomeEmailAsync(user.Email, user.Name);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Failed to send welcome email to {Email}", user.Email);
                }
            });
            
            // Log audit trail
            await LogAuditAsync(AuditAction.EMAIL_VERIFIED, user.Id, user.Email,
                AuditStatus.SUCCESS, "Email verified successfully", ipAddress, userAgent);

            return new MessageResponseDto
            {
                Message = "Email verified successfully. You can now log in.",
                Success = true
            };
            
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Email verification failed for token {Token}", token);
            throw;
        }

    }

    /// Authenticate user and generate tokens
    public async Task<AuthResponseDto> LoginAsync(LoginDto dto, string? ipAddress, string? userAgent)
    {
        try
        {
            var user = await _userRepository.GetByEmailAsync(dto.Email);

            if (user == null)
            {
                await LogAuditAsync(AuditAction.LOGIN_FAILED, null, dto.Email,
                    AuditStatus.FAILURE, "User not found", ipAddress, userAgent);
                throw new UnauthorizedAccessException("Invalid email or password");
            }

            // Check if account is locked
            if (user.Status == UserStatus.LOCKED && user.LockedUntil > DateTime.UtcNow)
            {
                await LogAuditAsync(AuditAction.LOGIN_FAILED, user.Id, user.Email,
                    AuditStatus.FAILURE, "Account locked", ipAddress, userAgent);
                throw new UnauthorizedAccessException(
                    $"Account is locked until {user.LockedUntil:yyyy-MM-dd HH:mm} UTC");
            }

            // Unlock account if lockout period has expired
            if (user.Status == UserStatus.LOCKED && user.LockedUntil <= DateTime.UtcNow)
            {
                user.Status = UserStatus.ACTIVE;
                user.FailedLoginAttempts = 0;
                user.LockedUntil = null;
            }

            // Check if email is verified
            if (user.Status == UserStatus.INACTIVE)
            {
                await LogAuditAsync(AuditAction.LOGIN_FAILED, user.Id, user.Email,
                    AuditStatus.FAILURE, "Email not verified", ipAddress, userAgent);
                throw new UnauthorizedAccessException("Please verify your email address before logging in");
            }

            var verifyResult = _passwordHasher.VerifyHashedPassword(user, user.Password, dto.Password);
            if (verifyResult == PasswordVerificationResult.Failed)
            {
                user.FailedLoginAttempts++;
                user.LastFailedLogin = DateTime.UtcNow;

                if (user.FailedLoginAttempts >= MAX_FAILED_ATTEMPTS)
                {
                    user.Status = UserStatus.LOCKED;
                    user.LockedUntil = DateTime.UtcNow.AddMinutes(LOCKOUT_DURATION_MINUTES);

                    await _userRepository.UpdateAsync(user);

                    await LogAuditAsync(AuditAction.ACCOUNT_LOCKED, user.Id, user.Email,
                        AuditStatus.SUCCESS, $"Account locked after {MAX_FAILED_ATTEMPTS} failed attempts", ipAddress,
                        userAgent);

                    throw new UnauthorizedAccessException(
                        $"Account locked due to multiple failed login attempts. Try again after {LOCKOUT_DURATION_MINUTES} minutes.");
                }

                await _userRepository.UpdateAsync(user);

                await LogAuditAsync(AuditAction.LOGIN_FAILED, user.Id, user.Email,
                    AuditStatus.FAILURE, $"Invalid password. Attempt {user.FailedLoginAttempts}/{MAX_FAILED_ATTEMPTS}",
                    ipAddress, userAgent);

                throw new UnauthorizedAccessException("Invalid email or password");
            }

            // Successful login - reset failed attempts
            user.FailedLoginAttempts = 0;
            user.LastFailedLogin = null;
            user.LastLogin = DateTime.UtcNow;

            // Generate tokens
            var accessToken = _jwtService.GenerateAccessToken(user.Id, user.Email, user.Role);
            var refreshToken = _jwtService.GenerateRefreshToken();

            // Store refresh token
            user.RefreshToken = refreshToken;
            user.RefreshTokenExpiry = DateTime.UtcNow.AddDays(REFRESH_TOKEN_EXPIRY_DAYS);
            user.LastUpdated = DateTime.UtcNow;
            user.UpdatedBy = user.Email;

            await _userRepository.UpdateAsync(user);
            // Log audit trail
            await LogAuditAsync(AuditAction.USER_LOGIN, user.Id, user.Email,
                AuditStatus.SUCCESS, "User logged in successfully", ipAddress, userAgent);

            return new AuthResponseDto
            {
                AccessToken = accessToken,
                RefreshToken = refreshToken,
                TokenType = "Bearer",
                ExpiresIn = int.Parse(_configuration["JwtSettings:AccessTokenExpiryMinutes"] ?? "60") *
                            60, // Convert to seconds
                User = MapToUserDto(user)
            };
        }
        catch (Exception e)
        {
            _logger.LogError(e, "Login failed for email {Email}", dto.Email);
            throw;
        }
    }
    
    // Log Out user by invalidating refresh token
    public async Task<MessageResponseDto> LogoutAsync(Guid userId, string? ipAddress, string? userAgent)
    {
        var user = await _userRepository.GetByIdAsync(userId);
        if (user == null)
        {
            throw new ArgumentException("User not found");
        }

        user.RefreshToken = null;
        user.RefreshTokenExpiry = null;
        user.LastUpdated = DateTime.UtcNow;
        user.UpdatedBy = user.Email;

        await _userRepository.UpdateAsync(user);

        await LogAuditAsync(AuditAction.USER_LOGOUT, userId, user.Email,
            AuditStatus.SUCCESS, "User logged out", ipAddress, userAgent);

        return new MessageResponseDto
        {
            Message = "Logged out successfully",
            Success = true
        };
    }
    
    // Generate Refresh Token using valid refresh token
    public async Task<AuthResponseDto> RefreshTokenAsync(string refreshToken, string? ipAddress, string? userAgent)
    {
        var user = await _userRepository.GetByRefreshTokenAsync(refreshToken);

        if (user == null || user.RefreshTokenExpiry < DateTime.UtcNow)
        {
            await LogAuditAsync(AuditAction.LOGIN_FAILED, null, null,
                AuditStatus.FAILURE, "Invalid or expired refresh token", ipAddress, userAgent);
            throw new UnauthorizedAccessException("Invalid or expired refresh token");
        }

        var newAccessToken = _jwtService.GenerateAccessToken(user.Id, user.Email, user.Role);
        var newRefreshToken = _jwtService.GenerateRefreshToken();

        user.RefreshToken = newRefreshToken;
        user.RefreshTokenExpiry = DateTime.UtcNow.AddDays(REFRESH_TOKEN_EXPIRY_DAYS);
        user.LastUpdated = DateTime.UtcNow;
        user.UpdatedBy = user.Email;

        await _userRepository.UpdateAsync(user);

        await LogAuditAsync(AuditAction.TOKEN_REFRESHED, user.Id, user.Email,
            AuditStatus.SUCCESS, "Token refreshed successfully", ipAddress, userAgent);

        return new AuthResponseDto
        {
            AccessToken = newAccessToken,
            RefreshToken = newRefreshToken,
            TokenType = "Bearer",
            ExpiresIn = int.Parse(_configuration["JwtSettings:AccessTokenExpiryMinutes"] ?? "60") * 60,
            User = MapToUserDto(user)
        };
    }
    
    // User Profile Retrieval
    public async Task<UserDto> GetUserProfileAsync(Guid userId)
    {
        var user = await _userRepository.GetByIdAsync(userId);
        if (user == null)
        {
            throw new ArgumentException("User not found");
        }

        return MapToUserDto(user);
    }
    
    // Forget Password - Generate reset token and send email
    public async Task<MessageResponseDto> ForgotPasswordAsync(ForgotPasswordDto forgotPasswordDto, string? ipAddress, string? userAgent)
    {
        try
        {
            var user = await _userRepository.GetByEmailAsync(forgotPasswordDto.Email);
    
            if (user != null && !user.IsDeleted)
            {
                var resetToken = GenerateSecureToken();
                user.PasswordResetToken = resetToken;
                user.PasswordResetTokenExpiry = DateTime.UtcNow.AddHours(PASSWORD_RESET_TOKEN_EXPIRY_HOURS);
                user.LastUpdated = DateTime.UtcNow;
                user.UpdatedBy = user.Email;
    
                await _userRepository.UpdateAsync(user);
    
                // Send password reset email
                _ = Task.Run(async () =>
                {
                    try
                    {
                        await _emailService.SendPasswordResetEmailAsync(user.Email, user.Name, resetToken);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Failed to send password reset email to {Email}", user.Email);
                    }
                });
    
                await LogAuditAsync(AuditAction.PASSWORD_RESET_REQUESTED, user.Id, user.Email,
                    AuditStatus.SUCCESS, "Password reset requested", ipAddress, userAgent);
            }
            else
            {
                // Log attempt even if user not found (for security monitoring)
                await LogAuditAsync(AuditAction.PASSWORD_RESET_REQUESTED, null, forgotPasswordDto.Email,
                    AuditStatus.FAILURE, "User not found", ipAddress, userAgent);
            }
    
            // Always return success message (don't reveal if user exists)
            return new MessageResponseDto
            {
                Message = "If your email is registered, you will receive a password reset link shortly.",
                Success = true
            };
        }
        catch (Exception e)
        {
            _logger.LogError(e, "Forgot password failed for email {Email}", forgotPasswordDto.Email);
            throw;
        }
    }
    
    // Password Reset - Validate token and update password
    public async Task<MessageResponseDto> ResetPasswordAsync(ResetPasswordDto resetPasswordDto, string? ipAddress, string? userAgent)
    {
        try
        {
            var user = await _userRepository.GetByPasswordResetTokenAsync(resetPasswordDto.Token);

            if (user == null)
            {
                await LogAuditAsync(AuditAction.PASSWORD_RESET_COMPLETED, null, null,
                    AuditStatus.FAILURE, "Invalid reset token", ipAddress, userAgent);
                throw new InvalidOperationException("Invalid or expired reset token");
            }

            // Check token expiry
            if (user.PasswordResetTokenExpiry < DateTime.UtcNow)
            {
                await LogAuditAsync(AuditAction.PASSWORD_RESET_COMPLETED, user.Id, user.Email,
                    AuditStatus.FAILURE, "Reset token expired", ipAddress, userAgent);
                throw new InvalidOperationException("Reset token has expired. Please request a new one.");
            }


            user.Password = _passwordHasher.HashPassword(user, resetPasswordDto.NewPassword);
            user.PasswordResetToken = null;
            user.PasswordResetTokenExpiry = null;
            user.FailedLoginAttempts = 0;
            user.LastFailedLogin = null;

            // Unlock account if locked
            if (user.Status == UserStatus.LOCKED)
            {
                user.Status = UserStatus.ACTIVE;
                user.LockedUntil = null;
            }

            // Invalidate all existing sessions
            user.RefreshToken = null;
            user.RefreshTokenExpiry = null;

            user.LastUpdated = DateTime.UtcNow;
            user.UpdatedBy = user.Email;

            await _userRepository.UpdateAsync(user);

            // Log audit trail
            await LogAuditAsync(AuditAction.PASSWORD_RESET_COMPLETED, user.Id, user.Email,
                AuditStatus.SUCCESS, "Password reset successfully", ipAddress, userAgent);

            return new MessageResponseDto
            {
                Message = "Password reset successfully. Please log in with your new password.",
                Success = true
            };
        }
        catch (Exception e)
        {
            _logger.LogError(e, "Password reset failed for token {Token}", resetPasswordDto.Token);
            throw;
        }
        
        
    }
    
    
    public async Task<AuthResponseDto> ExternalLoginAsync(ExternalAuthResult authResult, string? ipAddress, string? userAgent)
    
    {
        try
        {
            if (!authResult.IsValid)
            {
                await LogAuditAsync(AuditAction.LOGIN_FAILED, null, authResult.Email,
                    AuditStatus.FAILURE, $"Invalid {authResult.Provider} token", ipAddress, userAgent);
                throw new UnauthorizedAccessException(authResult.ErrorMessage ?? "Invalid external authentication");
            }
            
            var user = await _userRepository.GetByEmailAsync(authResult.Email);

            if (user == null)
            {
                user = new User
                {
                    Name = authResult.Name,
                    Email = authResult.Email.ToLower(),
                    Password = string.Empty, // No password for OAuth users
                    Role = UserRole.EXTERNAL_USER,
                    Status = UserStatus.ACTIVE, // Auto-verify OAuth users
                    LanguagePreference = "en",
                    ProfileCompleted = false,
                    ExternalLogins = new List<ExternalLoginInfo>
                    {
                        new ExternalLoginInfo
                        {
                            Provider = authResult.Provider,
                            ProviderUserId = authResult.ProviderUserId,
                            LinkedAt = DateTime.UtcNow
                        }
                    },
                    CreatedBy = authResult.Email,
                    LastUpdated = DateTime.UtcNow
                };
                
                var createdUser = await _userRepository.AddAsync(user);
                await LogAuditAsync(AuditAction.USER_REGISTERED, createdUser.Id, createdUser.Email,
                    AuditStatus.SUCCESS, $"User registered via {authResult.Provider}", ipAddress, userAgent);
                
                // Re-assign user for token generation
                user = createdUser;
            }
            else
            {
                // Check if this external login is already linked
                var existingLogin = user.ExternalLogins?.FirstOrDefault(
                    l => l.Provider == authResult.Provider && l.ProviderUserId == authResult.ProviderUserId);

                if (existingLogin == null)
                {
                    // Link new external provider to existing account
                    user.ExternalLogins ??= new List<ExternalLoginInfo>();
                    user.ExternalLogins.Add(new ExternalLoginInfo
                    {
                        Provider = authResult.Provider,
                        ProviderUserId = authResult.ProviderUserId,
                        LinkedAt = DateTime.UtcNow
                    });

                    user.LastUpdated = DateTime.UtcNow;
                    user.UpdatedBy = user.Email;

                    await _userRepository.UpdateAsync(user);

                    await LogAuditAsync(AuditAction.USER_LOGIN, user.Id, user.Email,
                        AuditStatus.SUCCESS, $"{authResult.Provider} account linked", ipAddress, userAgent);
                }
                // Ensure user account is active
                if (user.Status != UserStatus.ACTIVE)
                {
                    await LogAuditAsync(AuditAction.LOGIN_FAILED, user.Id, user.Email,
                        AuditStatus.FAILURE, "User account not active", ipAddress, userAgent);
                    throw new UnauthorizedAccessException("User account is not active");
                }
            }
            // Update last login
            user.LastLogin = DateTime.UtcNow;
            user.FailedLoginAttempts = 0;
            user.LastFailedLogin = null;

            // Generate tokens
            var accessToken = _jwtService.GenerateAccessToken(user.Id!, user.Email, user.Role);
            var refreshToken = _jwtService.GenerateRefreshToken();

            // Store refresh token
            user.RefreshToken = refreshToken;
            user.RefreshTokenExpiry = DateTime.UtcNow.AddDays(REFRESH_TOKEN_EXPIRY_DAYS);
            user.LastUpdated = DateTime.UtcNow;
            user.UpdatedBy = user.Email;

            await _userRepository.UpdateAsync(user);

            // Log audit trail
            await LogAuditAsync(AuditAction.USER_LOGIN, user.Id, user.Email,
                AuditStatus.SUCCESS, $"User logged in via {authResult.Provider}", ipAddress, userAgent);

            return new AuthResponseDto
            {
                AccessToken = accessToken,
                RefreshToken = refreshToken,
                TokenType = "Bearer",
                ExpiresIn = int.Parse(_configuration["JwtSettings:AccessTokenExpiryMinutes"] ?? "60") * 60,
                User = MapToUserDto(user)
            };
        }catch (Exception ex)
        {
            _logger.LogError(ex, "External login failed for {Provider} - {Email}", authResult.Provider, authResult.Email);
            throw;
        }
    }
    /// Generate cryptographically secure random token
    private string GenerateSecureToken()
    {
        var randomBytes = new byte[32];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomBytes);
        return Convert.ToBase64String(randomBytes).Replace("+", "-").Replace("/", "_").Replace("=", "");
    }
    
    private UserDto MapToUserDto(User user)
    {
        return new UserDto
        {
            Id = user.Id,
            Name = user.Name,
            Email = user.Email,
            Role = user.Role,
            Status = user.Status,
            LastLogin = user.LastLogin,
            LanguagePreference = user.LanguagePreference,
            NotificationPreference = user.NotificationPreference,
            ProfileCompleted = user.ProfileCompleted
        };
    }
    
    /// Log audit trail entry
    public async Task LogAuditAsync(string action, Guid? userId, string? userEmail,
        string status, string? details, string? ipAddress, string? userAgent)
    {
        try
        {
            var log = new AuditLog
            {
                Action = action,
                UserId = userId,
                UserEmail = userEmail,
                Status = status,
                Details = details,
                IpAddress = ipAddress,
                UserAgent = userAgent
            };
            await _auditLogRepository.AddAsync(log);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to create audit log entry for action {Action}", action);
        }
    }
    

    
}