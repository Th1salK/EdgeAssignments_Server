using EdgeAssignments.Core.Domain.Storage.Entities;

namespace EdgeAssignments.API.Services.Interfaces;

public interface IExternalAuthService
{
    Task<ExternalAuthResult> ValidateGoogleTokenAsync(string idToken);
    
    Task<ExternalAuthResult> ValidateMicrosoftTokenAsync(string idToken);
}

