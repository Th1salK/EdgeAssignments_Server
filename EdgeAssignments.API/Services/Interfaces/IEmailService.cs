namespace EdgeAssignments.API.Services.Interfaces;

public interface IEmailService
{
    
    Task SendEmailVerificationAsync(string email, string name, string verificationToken);
    
    Task SendPasswordResetEmailAsync(string email, string name, string resetToken);
    
    Task SendWelcomeEmailAsync(string email, string name);
}
