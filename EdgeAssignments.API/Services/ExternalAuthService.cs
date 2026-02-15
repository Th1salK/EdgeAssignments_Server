using EdgeAssignments.API.Services.Interfaces;
using EdgeAssignments.Core.Domain.Storage.Entities;
using Google.Apis.Auth;
using System.Net.Http.Headers;
using System.Text.Json;

namespace EdgeAssignments.API.Services;

public class ExternalAuthService : IExternalAuthService
{
    private readonly IConfiguration _configuration;
    private readonly HttpClient _httpClient;
    private readonly ILogger<ExternalAuthService> _logger;
    
    public ExternalAuthService(IConfiguration configuration, ILogger<ExternalAuthService> logger, HttpClient httpClient)
    {
        _configuration = configuration;
        _logger = logger;
        _httpClient = httpClient;
    }
    
    public async Task<ExternalAuthResult> ValidateGoogleTokenAsync(string idToken)
    {
        try
        {
            var clientId = _configuration["OAuth:Google:ClientId"];
            
            if (string.IsNullOrEmpty(clientId))
            {
                _logger.LogError("Google OAuth ClientId not configured");
                return new ExternalAuthResult 
                { 
                    IsValid = false, 
                    ErrorMessage = "Google OAuth not configured" 
                };
            }

            // Validate the ID token using Google's library
            var payload = await GoogleJsonWebSignature.ValidateAsync(idToken, new GoogleJsonWebSignature.ValidationSettings
            {
                Audience = new[] { clientId }
            });

            return new ExternalAuthResult
            {
                Provider = "Google",
                ProviderUserId = payload.Subject, // Google's unique user ID
                Email = payload.Email,
                Name = payload.Name,
                EmailVerified = payload.EmailVerified,
                IsValid = true
            };
        }
        catch (InvalidJwtException ex)
        {
            _logger.LogWarning(ex, "Invalid Google ID token");
            return new ExternalAuthResult 
            { 
                IsValid = false, 
                ErrorMessage = "Invalid Google ID token" 
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error validating Google token");
            return new ExternalAuthResult 
            { 
                IsValid = false, 
                ErrorMessage = "Error validating Google token" 
            };
        }
    }
    
    public async Task<ExternalAuthResult> ValidateMicrosoftTokenAsync(string accessToken)
    {
        try
        {
            // Call Microsoft Graph API to get user info (validates token)
            _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
            
            var response = await _httpClient.GetAsync("https://graph.microsoft.com/v1.0/me");
            
            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("Microsoft Graph API returned {StatusCode}", response.StatusCode);
                return new ExternalAuthResult 
                { 
                    IsValid = false, 
                    ErrorMessage = "Invalid Microsoft access token" 
                };
            }

            var content = await response.Content.ReadAsStringAsync();
            var userInfo = JsonSerializer.Deserialize<MicrosoftUserInfo>(content);

            if (userInfo == null || string.IsNullOrEmpty(userInfo.Id))
            {
                _logger.LogWarning("Failed to parse Microsoft user info");
                return new ExternalAuthResult 
                { 
                    IsValid = false, 
                    ErrorMessage = "Failed to retrieve user information" 
                };
            }

            return new ExternalAuthResult
            {
                Provider = "Microsoft",
                ProviderUserId = userInfo.Id,
                Email = userInfo.Mail ?? userInfo.UserPrincipalName ?? string.Empty,
                Name = userInfo.DisplayName ?? string.Empty,
                EmailVerified = true, // Microsoft verified emails
                IsValid = true
            };
        }
        catch (HttpRequestException ex)
        {
            _logger.LogError(ex, "HTTP error validating Microsoft token");
            return new ExternalAuthResult 
            { 
                IsValid = false, 
                ErrorMessage = "Error validating Microsoft token" 
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error validating Microsoft token");
            return new ExternalAuthResult 
            { 
                IsValid = false, 
                ErrorMessage = "Error validating Microsoft token" 
            };
        }
    }
    
    private class MicrosoftUserInfo
    {
        public string Id { get; set; } = string.Empty;
        public string? DisplayName { get; set; }
        public string? Mail { get; set; }
        public string? UserPrincipalName { get; set; }
    }
    
}