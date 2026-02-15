using EdgeAssignments.API.Services.Interfaces;
using EdgeAssignments.Core.Domain.Common.Repositories;
using EdgeAssignments.Core.Domain.Storage.Configs;
using EdgeAssignments.Core.Domain.Storage.Entities;
using MailKit.Net.Smtp;
using MailKit.Security;
using MimeKit;
namespace EdgeAssignments.API.Services;

public class EmailService : IEmailService
{
    
    private readonly SmtpSettings _smtpSettings;
    private readonly IAuditLogRepository _auditLogRepository;
    private readonly ILogger<EmailService> _logger;
    private readonly IConfiguration _configuration;
    
    public EmailService(
        SmtpSettings smtpSettings,
        IAuditLogRepository auditLogRepository,
        ILogger<EmailService> logger,
        IConfiguration configuration)
    {
        _smtpSettings = smtpSettings ?? throw new ArgumentNullException(nameof(smtpSettings));
        _auditLogRepository = auditLogRepository ?? throw new ArgumentNullException(nameof(auditLogRepository));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));

        // Validate SMTP configuration on startup
        ValidateSmtpSettings();
    }
    
    /// Validates that all required SMTP settings are configured.
    /// This runs at startup to fail fast if configuration is missing.
    private void ValidateSmtpSettings()
    {
        var errors = new List<string>();

        if (string.IsNullOrWhiteSpace(_smtpSettings.Host))
            errors.Add("SMTP Host is not configured");

        if (_smtpSettings.Port <= 0)
            errors.Add("SMTP Port is invalid");

        if (string.IsNullOrWhiteSpace(_smtpSettings.Username))
            errors.Add("SMTP Username is not configured");

        if (string.IsNullOrWhiteSpace(_smtpSettings.Password))
            errors.Add("SMTP Password is not configured");

        if (string.IsNullOrWhiteSpace(_smtpSettings.FromEmail))
            errors.Add("SMTP FromEmail is not configured");

        if (errors.Any())
        {
            var errorMessage = $"SMTP Configuration Errors: {string.Join(", ", errors)}";
            _logger.LogWarning(errorMessage);
            // Don't throw - allow app to start but log warnings
        }
        else
        {
            _logger.LogInformation("SMTP configuration validated successfully. Host: {Host}, Port: {Port}", 
                _smtpSettings.Host, _smtpSettings.Port);
        }
    }
    
    /// Sends email verification with activation link.
    /// Called after user registration to verify email address.
    public async Task SendEmailVerificationAsync(string email, string name, string verificationToken)
    {
        try
        {
            // Build verification URL from frontend configuration
            var verificationUrl = $"{_configuration["AppSettings:FrontendUrl"]}/verify-email?token={verificationToken}";

            var subject = "Verify Your Email Address - Edge Assignments";
            
            // Use pre-built HTML templates for professional appearance
            var htmlBody = EmailTemplates.GetEmailVerificationTemplate(name, verificationUrl);
            var textBody = EmailTemplates.GetEmailVerificationPlainText(name, verificationUrl);

            await SendEmailAsync(email, name, subject, htmlBody, textBody);

            _logger.LogInformation("Email verification sent successfully to {Email}", email);
        }
        catch (Exception ex)
        {
            // Log error but don't throw - registration should succeed even if email fails
            _logger.LogError(ex, "Failed to send email verification to {Email}", email);
            
            // Track failure in audit log for monitoring
            await LogEmailFailureAsync("EMAIL_VERIFICATION_FAILED", email, ex.Message);
            
            // IMPORTANT: Don't throw exception - fail gracefully
        }
    }
    
    /// Sends password reset email with secure reset link.
    /// Called when user requests password reset.
    public async Task SendPasswordResetEmailAsync(string email, string name, string resetToken)
    {
        try
        {
            // Build reset URL from frontend configuration
            var resetUrl = $"{_configuration["AppSettings:FrontendUrl"]}/reset-password?token={resetToken}";

            var subject = "Reset Your Password - Edge Assignments";
            
            // Use pre-built HTML templates
            var htmlBody = EmailTemplates.GetPasswordResetTemplate(name, resetUrl);
            var textBody = EmailTemplates.GetPasswordResetPlainText(name, resetUrl);

            await SendEmailAsync(email, name, subject, htmlBody, textBody);

            _logger.LogInformation("Password reset email sent successfully to {Email}", email);
        }
        catch (Exception ex)
        {
            // Log error but don't throw - password reset request should be recorded
            _logger.LogError(ex, "Failed to send password reset email to {Email}", email);
            
            // Track failure in audit log
            await LogEmailFailureAsync("PASSWORD_RESET_EMAIL_FAILED", email, ex.Message);
            
            // IMPORTANT: Don't throw exception - fail gracefully
        }
    }
    
    
    /// Sends welcome email after successful email verification.
    /// Optional - enhances user experience.
    public async Task SendWelcomeEmailAsync(string email, string name)
    {
        try
        {
            // Build login URL from frontend configuration
            var loginUrl = $"{_configuration["AppSettings:FrontendUrl"]}/login";

            var subject = "Welcome to Edge Assignments!";
            
            // Use pre-built HTML templates
            var htmlBody = EmailTemplates.GetWelcomeTemplate(name, loginUrl);
            var textBody = EmailTemplates.GetWelcomePlainText(name, loginUrl);

            await SendEmailAsync(email, name, subject, htmlBody, textBody);

            _logger.LogInformation("Welcome email sent successfully to {Email}", email);
        }
        catch (Exception ex)
        {
            // Log error but don't throw - this is a nice-to-have email
            _logger.LogError(ex, "Failed to send welcome email to {Email}", email);
            
            // Track failure in audit log
            await LogEmailFailureAsync("WELCOME_EMAIL_FAILED", email, ex.Message);
            
            // IMPORTANT: Don't throw exception - fail gracefully
        }
    }
    
    /// Core email sending method using MailKit SMTP client.
    private async Task SendEmailAsync(string toEmail, string toName, string subject, string htmlBody, string textBody)
    {
        // Validate configuration before attempting to send
        if (string.IsNullOrWhiteSpace(_smtpSettings.Host))
        {
            var errorMsg = "SMTP Host is not configured. Cannot send email.";
            _logger.LogError(errorMsg);
            throw new InvalidOperationException(errorMsg);
        }

        _logger.LogDebug("Preparing to send email to {Email} with subject: {Subject}", toEmail, subject);
        _logger.LogDebug("SMTP Config: Host={Host}, Port={Port}, EnableSsl={EnableSsl}, FromEmail={FromEmail}", 
            _smtpSettings.Host, _smtpSettings.Port, _smtpSettings.EnableSsl, _smtpSettings.FromEmail);

        // Step 1: Create the email message
        var message = new MimeMessage();

        // Set sender information from configuration
        message.From.Add(new MailboxAddress(
            _smtpSettings.FromName ?? "Edge Assignments", 
            _smtpSettings.FromEmail));

        // Set recipient information
        message.To.Add(new MailboxAddress(toName, toEmail));

        // Set subject
        message.Subject = subject;

        
        // This ensures compatibility with all email clients
        var bodyBuilder = new BodyBuilder
        {
            HtmlBody = htmlBody,
            TextBody = textBody
        };

        message.Body = bodyBuilder.ToMessageBody();

        // Send email using SMTP
        using var smtpClient = new SmtpClient();
        try
        {
            var secureSocketOptions = _smtpSettings.EnableSsl 
                ? SecureSocketOptions.StartTls  
                : SecureSocketOptions.None;    

            _logger.LogDebug("Connecting to SMTP server {Host}:{Port} with SSL={EnableSsl}", 
                _smtpSettings.Host, _smtpSettings.Port, _smtpSettings.EnableSsl);

            // Connect to SMTP server
            await smtpClient.ConnectAsync(
                _smtpSettings.Host, 
                _smtpSettings.Port, 
                secureSocketOptions);

            // Authenticate with SMTP server
            // SECURITY: Password is never logged
            await smtpClient.AuthenticateAsync(
                _smtpSettings.Username, 
                _smtpSettings.Password);

            // Send the email
            await smtpClient.SendAsync(message);

            _logger.LogInformation("Email sent successfully to {Email} with subject: {Subject}", toEmail, subject);
        }
        catch (Exception ex)
        {
            // Log detailed error for troubleshooting (without exposing password)
            _logger.LogError(ex, 
                "SMTP Error: Failed to send email to {Email}. Host: {Host}, Port: {Port}, EnableSsl: {EnableSsl}", 
                toEmail, _smtpSettings.Host, _smtpSettings.Port, _smtpSettings.EnableSsl);
            
            // Log to audit log for monitoring
            await LogEmailFailureAsync("SMTP_SEND_FAILED", toEmail, $"SMTP error: {ex.Message}");
            
            // Re-throw with a safe error message (no sensitive data)
            throw new InvalidOperationException($"Failed to send email to {toEmail}. Please check SMTP configuration.", ex);
        }
        finally
        {
            if (smtpClient.IsConnected)
            {
                await smtpClient.DisconnectAsync(true);
            }
        }
    }
    
    /// Logs email failures to AuditLog collection for monitoring and troubleshooting.
    private async Task LogEmailFailureAsync(string action, string email, string errorMessage)
    {
        try
        {
            var auditLog = new AuditLog
            {
                Action = action,
                UserEmail = email,
                Status = AuditStatus.FAILURE,
                ErrorMessage = errorMessage,
                Details = $"Failed to send email to {email}",
                Timestamp = DateTime.UtcNow
            };

            await _auditLogRepository.AddAsync(auditLog);
            
            _logger.LogDebug("Email failure logged to audit log: {Action} for {Email}", action, email);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to log email failure to audit log for {Email}", email);
        }
    }
    
}