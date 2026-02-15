using EdgeAssignments.Core.Domain.Common.Repositories;
using EdgeAssignments.Core.Domain.Storage.Configs;
using EdgeAssignments.Infrastructure.Persistence;
using EdgeAssignments.API.Services;
using EdgeAssignments.API.Services.Interfaces;
using EdgeAssignments.Core.Domain.Storage.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Extensions.Options;
using System.Text;


var builder = WebApplication.CreateBuilder(args);
// 1. Configure Application Settings
builder.Services.Configure<ApplicationSettings>(
    builder.Configuration.GetSection("ApplicationSettings"));

builder.Services.AddSingleton(sp =>
    sp.GetRequiredService<IOptions<ApplicationSettings>>().Value);

// 2. Register MongoDB Repository and HttpContextAccessor
builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped(typeof(IBaseRepository<>), typeof(MongoRepository<>));

// 3. Register concrete repositories
builder.Services.AddScoped<IUserRepository, UserRepository>();
builder.Services.AddScoped<IAuditLogRepository, AuditLogRepository>();

// 4. Register services
builder.Services.AddScoped<IAuthService, AuthService>();
builder.Services.AddScoped<IExternalAuthService, ExternalAuthService>();
builder.Services.AddScoped<IJwtService, JwtService>();
builder.Services.AddScoped<IEmailService, EmailService>();

// 5. Register SMTP config and provider if present
builder.Services.Configure<SmtpSettings>(builder.Configuration.GetSection("SmtpSettings"));
builder.Services.AddSingleton(sp => sp.GetRequiredService<IOptions<SmtpSettings>>().Value);

// 6. Password hasher for User
builder.Services.AddScoped<IPasswordHasher<User>, PasswordHasher<User>>();

// 7. HttpClient for external auth service (Microsoft Graph)
builder.Services.AddHttpClient<IExternalAuthService, ExternalAuthService>();

// 8. Configure JWT Authentication
var jwtSecretKey = builder.Configuration["JwtSettings:SecretKey"] 
    ?? throw new InvalidOperationException("JWT Secret Key not configured");
var jwtIssuer = builder.Configuration["JwtSettings:Issuer"] ?? "EdgeAssignments";
var jwtAudience = builder.Configuration["JwtSettings:Audience"] ?? "EdgeAssignments";

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.SaveToken = true;
    options.RequireHttpsMetadata = false; // Set to true in production
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = jwtIssuer,
        ValidAudience = jwtAudience,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSecretKey)),
        ClockSkew = TimeSpan.Zero
    };
});

builder.Services.AddAuthorization();

builder.Services.AddControllers()
    .AddNewtonsoftJson(); // Required for JSON Patch

// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
