namespace EdgeAssignments.API.Controllers;
using EdgeAssignments.API.Dtos.Get;
using EdgeAssignments.API.Dtos.Post;
using EdgeAssignments.API.Services.Interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;


[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly IAuthService _authService;
    private readonly IExternalAuthService _externalAuthService;
    private readonly ILogger<AuthController> _logger;
    
    public AuthController(
        IAuthService authService, 
        IExternalAuthService externalAuthService,
        ILogger<AuthController> logger)
    {
        _authService = authService;
        _externalAuthService = externalAuthService;
        _logger = logger;
    }
    
    
    /// Register a new user
    [HttpPost("register")]
    [ProducesResponseType(typeof(MessageResponseDto), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<ActionResult<MessageResponseDto>> Register([FromBody] RegisterDto dto)
    {
        try
        {
            var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
            var userAgent = HttpContext.Request.Headers["User-Agent"].ToString();

            var response = await _authService.RegisterAsync(dto, ipAddress, userAgent);
            return Ok(response);
        }
        catch (InvalidOperationException ex)
        {
            return BadRequest(new MessageResponseDto { Message = ex.Message, Success = false });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Registration error");
            return BadRequest(new MessageResponseDto { Message = "Registration failed. Please try again.", Success = false });
        }
    }
    
    /// Verify email address using verification token
    [HttpGet("verify-email")]
    [ProducesResponseType(typeof(MessageResponseDto), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<ActionResult<MessageResponseDto>> VerifyEmail([FromQuery] string token)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(token))
            {
                return BadRequest(new MessageResponseDto { Message = "Verification token is required", Success = false });
            }

            var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
            var userAgent = HttpContext.Request.Headers["User-Agent"].ToString();

            var response = await _authService.VerifyEmailAsync(token, ipAddress, userAgent);
            return Ok(response);
        }
        catch (InvalidOperationException ex)
        {
            return BadRequest(new MessageResponseDto { Message = ex.Message, Success = false });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Email verification error");
            return BadRequest(new MessageResponseDto { Message = "Email verification failed. Please try again.", Success = false });
        }
    }
    
    
    /// Authenticate user and return JWT tokens
    [HttpPost("login")]
    [ProducesResponseType(typeof(AuthResponseDto), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<ActionResult<AuthResponseDto>> Login([FromBody] LoginDto dto)
    {
        try
        {
            var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
            var userAgent = HttpContext.Request.Headers["User-Agent"].ToString();

            var response = await _authService.LoginAsync(dto, ipAddress, userAgent);
            return Ok(response);
        }
        catch (UnauthorizedAccessException ex)
        {
            return Unauthorized(new MessageResponseDto { Message = ex.Message, Success = false });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Login error");
            return Unauthorized(new MessageResponseDto { Message = "Login failed. Please try again.", Success = false });
        }
    }
    
    
    /// Logout user and invalidate refresh token
    [HttpPost("logout")]
    [Authorize]
    [ProducesResponseType(typeof(MessageResponseDto), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<ActionResult<MessageResponseDto>> Logout()
    {
        try
        {
            // Extract user ID from JWT token (claim is a string representation of a Guid)
            var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

            if (string.IsNullOrEmpty(userIdClaim) || !Guid.TryParse(userIdClaim, out var userId))
            {
                return Unauthorized(new MessageResponseDto { Message = "Invalid token", Success = false });
            }

            var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
            var userAgent = HttpContext.Request.Headers["User-Agent"].ToString();

            var response = await _authService.LogoutAsync(userId, ipAddress, userAgent);
            return Ok(response);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Logout error");
            return BadRequest(new MessageResponseDto { Message = "Logout failed. Please try again.", Success = false });
        }
    }
    
    
    /// Refresh access token using refresh token
    [HttpPost("refresh-token")]
    [ProducesResponseType(typeof(AuthResponseDto), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<ActionResult<AuthResponseDto>> RefreshToken([FromBody] RefreshTokenDto dto)
    {
        try
        {
            var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
            var userAgent = HttpContext.Request.Headers["User-Agent"].ToString();

            var response = await _authService.RefreshTokenAsync(dto.RefreshToken, ipAddress, userAgent);
            return Ok(response);
        }
        catch (UnauthorizedAccessException ex)
        {
            return Unauthorized(new MessageResponseDto { Message = ex.Message, Success = false });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Token refresh error");
            return Unauthorized(new MessageResponseDto { Message = "Token refresh failed. Please log in again.", Success = false });
        }
    }
    
    /// Get authenticated user profile
    [HttpGet("profile")]
    [Authorize]
    [ProducesResponseType(typeof(UserDto), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<ActionResult<UserDto>> GetProfile()
    {
        try
        {
            // Extract user ID from JWT token (claim is a string representation of a Guid)
            var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

            if (string.IsNullOrEmpty(userIdClaim) || !Guid.TryParse(userIdClaim, out var userId))
            {
                return Unauthorized(new MessageResponseDto { Message = "Invalid token", Success = false });
            }

            var response = await _authService.GetUserProfileAsync(userId);
            return Ok(response);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Get profile error");
            return BadRequest(new MessageResponseDto { Message = "Failed to retrieve profile", Success = false });
        }
    }
    
    /// Request password reset email
    [HttpPost("forgot-password")]
    [ProducesResponseType(typeof(MessageResponseDto), StatusCodes.Status200OK)]
    public async Task<ActionResult<MessageResponseDto>> ForgotPassword([FromBody] ForgotPasswordDto dto)
    {
        try
        {
            var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
            var userAgent = HttpContext.Request.Headers["User-Agent"].ToString();

            var response = await _authService.ForgotPasswordAsync(dto, ipAddress, userAgent);
            return Ok(response);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Forgot password error");
            // Always return success to prevent user enumeration
            return Ok(new MessageResponseDto 
            { 
                Message = "If your email is registered, you will receive a password reset link shortly.", 
                Success = true 
            });
        }
    }
    
    /// Reset password using reset token
    [HttpPost("reset-password")]
    [ProducesResponseType(typeof(MessageResponseDto), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<ActionResult<MessageResponseDto>> ResetPassword([FromBody] ResetPasswordDto dto)
    {
        try
        {
            var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
            var userAgent = HttpContext.Request.Headers["User-Agent"].ToString();

            var response = await _authService.ResetPasswordAsync(dto, ipAddress, userAgent);
            return Ok(response);
        }
        catch (InvalidOperationException ex)
        {
            return BadRequest(new MessageResponseDto { Message = ex.Message, Success = false });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Password reset error");
            return BadRequest(new MessageResponseDto { Message = "Password reset failed. Please try again.", Success = false });
        }
    }

    
    /// Authenticate with Google OAuth
    [HttpPost("google")]
    [ProducesResponseType(typeof(AuthResponseDto), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<ActionResult<AuthResponseDto>> GoogleLogin([FromBody] GoogleAuthDto dto)
    {
        try
        {
            var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
            var userAgent = HttpContext.Request.Headers["User-Agent"].ToString();

            // Validate Google ID token
            var authResult = await _externalAuthService.ValidateGoogleTokenAsync(dto.IdToken);

            if (!authResult.IsValid)
            {
                return Unauthorized(new MessageResponseDto 
                { 
                    Message = authResult.ErrorMessage ?? "Invalid Google authentication", 
                    Success = false 
                });
            }

            // Process external login
            var response = await _authService.ExternalLoginAsync(authResult, ipAddress, userAgent);
            return Ok(response);
        }
        catch (UnauthorizedAccessException ex)
        {
            return Unauthorized(new MessageResponseDto { Message = ex.Message, Success = false });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Google login error");
            return Unauthorized(new MessageResponseDto { Message = "Google login failed. Please try again.", Success = false });
        }
    }

    
    /// Authenticate with Microsoft OAuth
    [HttpPost("microsoft")]
    [ProducesResponseType(typeof(AuthResponseDto), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<ActionResult<AuthResponseDto>> MicrosoftLogin([FromBody] MicrosoftAuthDto dto)
    {
        try
        {
            var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
            var userAgent = HttpContext.Request.Headers["User-Agent"].ToString();

            // Validate Microsoft access token
            var authResult = await _externalAuthService.ValidateMicrosoftTokenAsync(dto.AccessToken);

            if (!authResult.IsValid)
            {
                return Unauthorized(new MessageResponseDto 
                { 
                    Message = authResult.ErrorMessage ?? "Invalid Microsoft authentication", 
                    Success = false 
                });
            }

            // Process external login
            var response = await _authService.ExternalLoginAsync(authResult, ipAddress, userAgent);
            return Ok(response);
        }
        catch (UnauthorizedAccessException ex)
        {
            return Unauthorized(new MessageResponseDto { Message = ex.Message, Success = false });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Microsoft login error");
            return Unauthorized(new MessageResponseDto { Message = "Microsoft login failed. Please try again.", Success = false });
        }
    }
}