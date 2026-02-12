namespace EdgeAssignments.API.Services;


public static class EmailTemplates
{
    
    public static string GetEmailVerificationTemplate(string userName, string verificationLink)
    {
        return $@"
<!DOCTYPE html>
<html lang='en'>
<head>
    <meta charset='UTF-8'>
    <meta name='viewport' content='width=device-width, initial-scale=1.0'>
    <title>Verify Your Email</title>
</head>
<body style='margin: 0; padding: 0; font-family: Arial, Helvetica, sans-serif; background-color: #f4f4f4;'>
    <table role='presentation' style='width: 100%; border-collapse: collapse; background-color: #f4f4f4;'>
        <tr>
            <td align='center' style='padding: 40px 0;'>
                <table role='presentation' style='width: 600px; max-width: 100%; border-collapse: collapse; background-color: #ffffff; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1);'>
                    <!-- Header -->
                    <tr>
                        <td style='background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 40px 30px; text-align: center; border-radius: 8px 8px 0 0;'>
                            <h1 style='margin: 0; color: #ffffff; font-size: 28px; font-weight: 600;'>Edge Assignments</h1>
                        </td>
                    </tr>
                    
                    <!-- Content -->
                    <tr>
                        <td style='padding: 40px 30px;'>
                            <h2 style='margin: 0 0 20px 0; color: #333333; font-size: 24px; font-weight: 600;'>Verify Your Email Address</h2>
                            <p style='margin: 0 0 15px 0; color: #555555; font-size: 16px; line-height: 1.6;'>
                                Hello <strong>{userName}</strong>,
                            </p>
                            <p style='margin: 0 0 25px 0; color: #555555; font-size: 16px; line-height: 1.6;'>
                                Thank you for registering with Edge Assignments! To complete your registration and activate your account, please verify your email address by clicking the button below.
                            </p>
                            
                            <!-- CTA Button -->
                            <table role='presentation' style='margin: 30px 0; width: 100%;'>
                                <tr>
                                    <td align='center'>
                                        <a href='{verificationLink}' 
                                           style='display: inline-block; padding: 16px 40px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: #ffffff; text-decoration: none; border-radius: 6px; font-weight: 600; font-size: 16px;'>
                                            Verify Email Address
                                        </a>
                                    </td>
                                </tr>
                            </table>
                            
                            <p style='margin: 25px 0 15px 0; color: #555555; font-size: 14px; line-height: 1.6;'>
                                Or copy and paste this link into your browser:
                            </p>
                            <p style='margin: 0 0 20px 0; padding: 12px; background-color: #f8f9fa; border-left: 4px solid #667eea; word-break: break-all; font-size: 13px; color: #667eea;'>
                                <a href='{verificationLink}' style='color: #667eea; text-decoration: none;'>{verificationLink}</a>
                            </p>
                            
                            <p style='margin: 0; color: #888888; font-size: 14px; line-height: 1.6;'>
                                <strong>Note:</strong> This verification link will expire in 24 hours for security reasons.
                            </p>
                        </td>
                    </tr>
                    
                    <!-- Footer -->
                    <tr>
                        <td style='background-color: #f8f9fa; padding: 30px; text-align: center; border-radius: 0 0 8px 8px; border-top: 1px solid #e9ecef;'>
                            <p style='margin: 0 0 10px 0; color: #888888; font-size: 13px; line-height: 1.6;'>
                                If you didn't create an account with Edge Assignments, please ignore this email.
                            </p>
                            <p style='margin: 0; color: #aaaaaa; font-size: 12px;'>
                                &copy; 2026 Edge Assignments. All rights reserved.
                            </p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>";
    }

    /// <summary>
    /// Generates HTML template for password reset
    /// </summary>
    /// <param name="userName">The user's name for personalization</param>
    /// <param name="resetLink">The full password reset URL</param>
    /// <returns>HTML email content</returns>
    public static string GetPasswordResetTemplate(string userName, string resetLink)
    {
        return $@"
<!DOCTYPE html>
<html lang='en'>
<head>
    <meta charset='UTF-8'>
    <meta name='viewport' content='width=device-width, initial-scale=1.0'>
    <title>Reset Your Password</title>
</head>
<body style='margin: 0; padding: 0; font-family: Arial, Helvetica, sans-serif; background-color: #f4f4f4;'>
    <table role='presentation' style='width: 100%; border-collapse: collapse; background-color: #f4f4f4;'>
        <tr>
            <td align='center' style='padding: 40px 0;'>
                <table role='presentation' style='width: 600px; max-width: 100%; border-collapse: collapse; background-color: #ffffff; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1);'>
                    <!-- Header -->
                    <tr>
                        <td style='background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); padding: 40px 30px; text-align: center; border-radius: 8px 8px 0 0;'>
                            <h1 style='margin: 0; color: #ffffff; font-size: 28px; font-weight: 600;'>Edge Assignments</h1>
                        </td>
                    </tr>
                    
                    <!-- Content -->
                    <tr>
                        <td style='padding: 40px 30px;'>
                            <h2 style='margin: 0 0 20px 0; color: #333333; font-size: 24px; font-weight: 600;'>Password Reset Request</h2>
                            <p style='margin: 0 0 15px 0; color: #555555; font-size: 16px; line-height: 1.6;'>
                                Hello <strong>{userName}</strong>,
                            </p>
                            <p style='margin: 0 0 25px 0; color: #555555; font-size: 16px; line-height: 1.6;'>
                                We received a request to reset your password for your Edge Assignments account. Click the button below to create a new password.
                            </p>
                            
                            <!-- CTA Button -->
                            <table role='presentation' style='margin: 30px 0; width: 100%;'>
                                <tr>
                                    <td align='center'>
                                        <a href='{resetLink}' 
                                           style='display: inline-block; padding: 16px 40px; background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); color: #ffffff; text-decoration: none; border-radius: 6px; font-weight: 600; font-size: 16px;'>
                                            Reset Password
                                        </a>
                                    </td>
                                </tr>
                            </table>
                            
                            <p style='margin: 25px 0 15px 0; color: #555555; font-size: 14px; line-height: 1.6;'>
                                Or copy and paste this link into your browser:
                            </p>
                            <p style='margin: 0 0 20px 0; padding: 12px; background-color: #f8f9fa; border-left: 4px solid #f5576c; word-break: break-all; font-size: 13px; color: #f5576c;'>
                                <a href='{resetLink}' style='color: #f5576c; text-decoration: none;'>{resetLink}</a>
                            </p>
                            
                            <p style='margin: 0 0 15px 0; color: #888888; font-size: 14px; line-height: 1.6;'>
                                <strong>Note:</strong> This password reset link will expire in 1 hour for security reasons.
                            </p>
                            
                            <!-- Security Warning Box -->
                            <div style='margin: 25px 0 0 0; padding: 15px; background-color: #fff3cd; border-left: 4px solid #ffc107; border-radius: 4px;'>
                                <p style='margin: 0; color: #856404; font-size: 14px; line-height: 1.6;'>
                                    <strong>⚠️ Security Notice:</strong> If you didn't request this password reset, please ignore this email or contact our support team immediately if you're concerned about your account security.
                                </p>
                            </div>
                        </td>
                    </tr>
                    
                    <!-- Footer -->
                    <tr>
                        <td style='background-color: #f8f9fa; padding: 30px; text-align: center; border-radius: 0 0 8px 8px; border-top: 1px solid #e9ecef;'>
                            <p style='margin: 0 0 10px 0; color: #888888; font-size: 13px; line-height: 1.6;'>
                                Need help? Contact us at <a href='mailto:support@edgeassignments.com' style='color: #667eea; text-decoration: none;'>support@edgeassignments.com</a>
                            </p>
                            <p style='margin: 0; color: #aaaaaa; font-size: 12px;'>
                                &copy; 2026 Edge Assignments. All rights reserved.
                            </p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>";
    }

    /// <summary>
    /// Generates HTML template for security alerts
    /// </summary>
    /// <param name="userName">The user's name for personalization</param>
    /// <param name="alertMessage">The security alert details</param>
    /// <param name="timestamp">The time of the security event</param>
    /// <param name="ipAddress">The IP address associated with the event (optional)</param>
    /// <returns>HTML email content</returns>
    public static string GetSecurityAlertTemplate(string userName, string alertMessage, DateTime timestamp, string? ipAddress = null)
    {
        var ipInfo = !string.IsNullOrEmpty(ipAddress) 
            ? $@"
                            <tr>
                                <td style='padding: 10px 15px; border-bottom: 1px solid #e9ecef;'>
                                    <strong style='color: #333333;'>IP Address:</strong>
                                </td>
                                <td style='padding: 10px 15px; border-bottom: 1px solid #e9ecef; color: #555555;'>
                                    {ipAddress}
                                </td>
                            </tr>" 
            : "";

        return $@"
<!DOCTYPE html>
<html lang='en'>
<head>
    <meta charset='UTF-8'>
    <meta name='viewport' content='width=device-width, initial-scale=1.0'>
    <title>Security Alert</title>
</head>
<body style='margin: 0; padding: 0; font-family: Arial, Helvetica, sans-serif; background-color: #f4f4f4;'>
    <table role='presentation' style='width: 100%; border-collapse: collapse; background-color: #f4f4f4;'>
        <tr>
            <td align='center' style='padding: 40px 0;'>
                <table role='presentation' style='width: 600px; max-width: 100%; border-collapse: collapse; background-color: #ffffff; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1);'>
                    <!-- Header -->
                    <tr>
                        <td style='background: linear-gradient(135deg, #fc5c7d 0%, #6a82fb 100%); padding: 40px 30px; text-align: center; border-radius: 8px 8px 0 0;'>
                            <h1 style='margin: 0; color: #ffffff; font-size: 28px; font-weight: 600;'>🔒 Security Alert</h1>
                        </td>
                    </tr>
                    
                    <!-- Content -->
                    <tr>
                        <td style='padding: 40px 30px;'>
                            <h2 style='margin: 0 0 20px 0; color: #333333; font-size: 24px; font-weight: 600;'>Account Security Notification</h2>
                            <p style='margin: 0 0 15px 0; color: #555555; font-size: 16px; line-height: 1.6;'>
                                Hello <strong>{userName}</strong>,
                            </p>
                            <p style='margin: 0 0 25px 0; color: #555555; font-size: 16px; line-height: 1.6;'>
                                We detected important activity on your Edge Assignments account and wanted to notify you immediately.
                            </p>
                            
                            <!-- Alert Box -->
                            <div style='margin: 25px 0; padding: 20px; background-color: #fff3cd; border-left: 4px solid #ffc107; border-radius: 4px;'>
                                <p style='margin: 0 0 10px 0; color: #856404; font-size: 16px; font-weight: 600;'>
                                    ⚠️ Security Event Detected
                                </p>
                                <p style='margin: 0; color: #856404; font-size: 15px; line-height: 1.6;'>
                                    {alertMessage}
                                </p>
                            </div>
                            
                            <!-- Event Details Table -->
                            <h3 style='margin: 30px 0 15px 0; color: #333333; font-size: 18px; font-weight: 600;'>Event Details</h3>
                            <table style='width: 100%; border-collapse: collapse; background-color: #f8f9fa; border-radius: 4px; overflow: hidden;'>
                                <tr>
                                    <td style='padding: 10px 15px; border-bottom: 1px solid #e9ecef;'>
                                        <strong style='color: #333333;'>Date & Time:</strong>
                                    </td>
                                    <td style='padding: 10px 15px; border-bottom: 1px solid #e9ecef; color: #555555;'>
                                        {timestamp:yyyy-MM-dd HH:mm:ss} UTC
                                    </td>
                                </tr>{ipInfo}
                            </table>
                            
                            <!-- Action Required Box -->
                            <div style='margin: 30px 0 0 0; padding: 20px; background-color: #f8d7da; border-left: 4px solid #dc3545; border-radius: 4px;'>
                                <p style='margin: 0 0 10px 0; color: #721c24; font-size: 16px; font-weight: 600;'>
                                    🛡️ Was This You?
                                </p>
                                <p style='margin: 0 0 15px 0; color: #721c24; font-size: 14px; line-height: 1.6;'>
                                    If you recognize this activity, you can safely ignore this email.
                                </p>
                                <p style='margin: 0; color: #721c24; font-size: 14px; line-height: 1.6;'>
                                    If you <strong>did not</strong> perform this action, please secure your account immediately by:
                                </p>
                                <ul style='margin: 10px 0 0 0; padding-left: 20px; color: #721c24;'>
                                    <li style='margin: 5px 0;'>Changing your password</li>
                                    <li style='margin: 5px 0;'>Reviewing your recent account activity</li>
                                    <li style='margin: 5px 0;'>Contacting our support team</li>
                                </ul>
                            </div>
                        </td>
                    </tr>
                    
                    <!-- Footer -->
                    <tr>
                        <td style='background-color: #f8f9fa; padding: 30px; text-align: center; border-radius: 0 0 8px 8px; border-top: 1px solid #e9ecef;'>
                            <p style='margin: 0 0 10px 0; color: #888888; font-size: 13px; line-height: 1.6;'>
                                For immediate assistance, contact us at <a href='mailto:security@edgeassignments.com' style='color: #667eea; text-decoration: none;'>security@edgeassignments.com</a>
                            </p>
                            <p style='margin: 0; color: #aaaaaa; font-size: 12px;'>
                                &copy; 2026 Edge Assignments. All rights reserved.
                            </p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>";
    }

    /// <summary>
    /// Generates HTML template for welcome email (after verification)
    /// </summary>
    /// <param name="userName">The user's name for personalization</param>
    /// <param name="loginUrl">The login page URL</param>
    /// <returns>HTML email content</returns>
    public static string GetWelcomeTemplate(string userName, string loginUrl)
    {
        return $@"
<!DOCTYPE html>
<html lang='en'>
<head>
    <meta charset='UTF-8'>
    <meta name='viewport' content='width=device-width, initial-scale=1.0'>
    <title>Welcome to Edge Assignments</title>
</head>
<body style='margin: 0; padding: 0; font-family: Arial, Helvetica, sans-serif; background-color: #f4f4f4;'>
    <table role='presentation' style='width: 100%; border-collapse: collapse; background-color: #f4f4f4;'>
        <tr>
            <td align='center' style='padding: 40px 0;'>
                <table role='presentation' style='width: 600px; max-width: 100%; border-collapse: collapse; background-color: #ffffff; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1);'>
                    <!-- Header -->
                    <tr>
                        <td style='background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%); padding: 40px 30px; text-align: center; border-radius: 8px 8px 0 0;'>
                            <h1 style='margin: 0; color: #ffffff; font-size: 28px; font-weight: 600;'>🎉 Welcome Aboard!</h1>
                        </td>
                    </tr>
                    
                    <!-- Content -->
                    <tr>
                        <td style='padding: 40px 30px;'>
                            <h2 style='margin: 0 0 20px 0; color: #333333; font-size: 24px; font-weight: 600;'>Your Account is Active!</h2>
                            <p style='margin: 0 0 15px 0; color: #555555; font-size: 16px; line-height: 1.6;'>
                                Hello <strong>{userName}</strong>,
                            </p>
                            <p style='margin: 0 0 25px 0; color: #555555; font-size: 16px; line-height: 1.6;'>
                                Your email has been verified successfully! You're all set to start using Edge Assignments and collaborate with your team.
                            </p>
                            
                            <!-- CTA Button -->
                            <table role='presentation' style='margin: 30px 0; width: 100%;'>
                                <tr>
                                    <td align='center'>
                                        <a href='{loginUrl}' 
                                           style='display: inline-block; padding: 16px 40px; background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%); color: #ffffff; text-decoration: none; border-radius: 6px; font-weight: 600; font-size: 16px;'>
                                            Login to Your Account
                                        </a>
                                    </td>
                                </tr>
                            </table>
                            
                            <!-- Getting Started Section -->
                            <h3 style='margin: 30px 0 15px 0; color: #333333; font-size: 18px; font-weight: 600;'>Getting Started</h3>
                            <div style='background-color: #f8f9fa; padding: 20px; border-radius: 6px;'>
                                <table style='width: 100%; border-collapse: collapse;'>
                                    <tr>
                                        <td style='padding: 10px 0; vertical-align: top;'>
                                            <span style='display: inline-block; width: 30px; height: 30px; background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%); color: #ffffff; text-align: center; line-height: 30px; border-radius: 50%; font-weight: 600; margin-right: 10px;'>1</span>
                                            <strong style='color: #333333;'>Complete Your Profile</strong>
                                            <p style='margin: 5px 0 0 40px; color: #666666; font-size: 14px;'>Add your details and preferences</p>
                                        </td>
                                    </tr>
                                    <tr>
                                        <td style='padding: 10px 0; vertical-align: top;'>
                                            <span style='display: inline-block; width: 30px; height: 30px; background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%); color: #ffffff; text-align: center; line-height: 30px; border-radius: 50%; font-weight: 600; margin-right: 10px;'>2</span>
                                            <strong style='color: #333333;'>Explore Assignments</strong>
                                            <p style='margin: 5px 0 0 40px; color: #666666; font-size: 14px;'>Browse and manage your tasks</p>
                                        </td>
                                    </tr>
                                    <tr>
                                        <td style='padding: 10px 0; vertical-align: top;'>
                                            <span style='display: inline-block; width: 30px; height: 30px; background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%); color: #ffffff; text-align: center; line-height: 30px; border-radius: 50%; font-weight: 600; margin-right: 10px;'>3</span>
                                            <strong style='color: #333333;'>Connect with Your Team</strong>
                                            <p style='margin: 5px 0 0 40px; color: #666666; font-size: 14px;'>Collaborate and stay productive</p>
                                        </td>
                                    </tr>
                                </table>
                            </div>
                        </td>
                    </tr>
                    
                    <!-- Footer -->
                    <tr>
                        <td style='background-color: #f8f9fa; padding: 30px; text-align: center; border-radius: 0 0 8px 8px; border-top: 1px solid #e9ecef;'>
                            <p style='margin: 0 0 10px 0; color: #888888; font-size: 13px; line-height: 1.6;'>
                                Need help getting started? Contact us at <a href='mailto:support@edgeassignments.com' style='color: #667eea; text-decoration: none;'>support@edgeassignments.com</a>
                            </p>
                            <p style='margin: 0; color: #aaaaaa; font-size: 12px;'>
                                &copy; 2026 Edge Assignments. All rights reserved.
                            </p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>";
    }

    /// <summary>
    /// Generates plain text version of email verification content
    /// Used as fallback for email clients that don't support HTML
    /// </summary>
    public static string GetEmailVerificationPlainText(string userName, string verificationLink)
    {
        return $@"
Edge Assignments - Verify Your Email Address

Hello {userName},

Thank you for registering with Edge Assignments! To complete your registration and activate your account, please verify your email address.

Verification Link:
{verificationLink}

Note: This verification link will expire in 24 hours for security reasons.

If you didn't create an account with Edge Assignments, please ignore this email.

---
© 2026 Edge Assignments. All rights reserved.
";
    }

    /// <summary>
    /// Generates plain text version of password reset content
    /// </summary>
    public static string GetPasswordResetPlainText(string userName, string resetLink)
    {
        return $@"
Edge Assignments - Password Reset Request

Hello {userName},

We received a request to reset your password for your Edge Assignments account.

Password Reset Link:
{resetLink}

Note: This password reset link will expire in 1 hour for security reasons.

SECURITY NOTICE: If you didn't request this password reset, please ignore this email or contact our support team immediately if you're concerned about your account security.

Need help? Contact us at support@edgeassignments.com

---
© 2026 Edge Assignments. All rights reserved.
";
    }

    /// <summary>
    /// Generates plain text version of security alert content
    /// </summary>
    public static string GetSecurityAlertPlainText(string userName, string alertMessage, DateTime timestamp, string? ipAddress = null)
    {
        var ipInfo = !string.IsNullOrEmpty(ipAddress) ? $"\nIP Address: {ipAddress}" : "";
        
        return $@"
Edge Assignments - Security Alert

Hello {userName},

We detected important activity on your Edge Assignments account and wanted to notify you immediately.

SECURITY EVENT DETECTED:
{alertMessage}

Event Details:
Date & Time: {timestamp:yyyy-MM-dd HH:mm:ss} UTC{ipInfo}

WAS THIS YOU?

If you recognize this activity, you can safely ignore this email.

If you did NOT perform this action, please secure your account immediately by:
- Changing your password
- Reviewing your recent account activity
- Contacting our support team

For immediate assistance, contact us at security@edgeassignments.com

---
© 2026 Edge Assignments. All rights reserved.
";
    }

    /// <summary>
    /// Generates plain text version of welcome email content
    /// </summary>
    public static string GetWelcomePlainText(string userName, string loginUrl)
    {
        return $@"
Edge Assignments - Welcome Aboard!

Hello {userName},

Your email has been verified successfully! You're all set to start using Edge Assignments and collaborate with your team.

Login to Your Account:
{loginUrl}

Getting Started:
1. Complete Your Profile - Add your details and preferences
2. Explore Assignments - Browse and manage your tasks
3. Connect with Your Team - Collaborate and stay productive

Need help getting started? Contact us at support@edgeassignments.com

---
© 2026 Edge Assignments. All rights reserved.
";
    }
}
