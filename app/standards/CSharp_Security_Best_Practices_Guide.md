# C# Programming Security Best Practices Guide

**Version:** 1.0  
**Last Updated:** March 2026  
**Author:** Matrix Agent  
**Applicable Standards:** NIST SP 800-53 Rev. 5, OWASP Top Ten 2021, DISA STIG V6, CIS Benchmark Level 2, FIPS 140-3

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [C# 12 and .NET 8 Security Features](#c-12-and-net-8-security-features)
3. [Secure Coding in ASP.NET Core](#secure-coding-in-aspnet-core)
4. [Input Validation and Sanitization](#input-validation-and-sanitization)
5. [Authentication and Authorization](#authentication-and-authorization)
6. [Entity Framework Security](#entity-framework-security)
7. [Cryptography with System.Security.Cryptography](#cryptography-with-systemsecuritycryptography)
8. [OWASP Top Ten Mitigations for .NET](#owasp-top-ten-mitigations-for-net)
9. [NIST SP 800-53 Compliance](#nist-sp-800-53-compliance)
10. [DISA STIG Requirements](#disa-stig-requirements)
11. [CIS Benchmark Level 2 Controls](#cis-benchmark-level-2-controls)
12. [FIPS 140-3 Cryptographic Requirements](#fips-140-3-cryptographic-requirements)
13. [Compliance Checklists](#compliance-checklists)
14. [References](#references)

---

## Executive Summary

This guide provides comprehensive security best practices for C# and .NET application development, aligned with major security compliance frameworks. It covers the latest C# 12 and .NET 8 security features, secure coding patterns for ASP.NET Core applications, and detailed mappings to NIST, OWASP, DISA STIG, CIS, and FIPS requirements.

**Key Objectives:**
- Implement defense-in-depth security strategies
- Prevent common vulnerabilities (injection, XSS, CSRF, broken authentication)
- Ensure cryptographic compliance with federal standards
- Enable continuous security monitoring and auditing

---

## C# 12 and .NET 8 Security Features

### 1. Language-Level Security Improvements

#### Primary Constructors with Validation

```csharp
public class SecureUser(string username, string email)
{
    // Validate inputs in primary constructor
    public string Username { get; } = ValidateUsername(username);
    public string Email { get; } = ValidateEmail(email);
    
    private static string ValidateUsername(string username)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(username);
        if (username.Length < 3 || username.Length > 50)
            throw new ArgumentOutOfRangeException(nameof(username), 
                "Username must be 3-50 characters");
        if (!Regex.IsMatch(username, @"^[a-zA-Z0-9_]+$"))
            throw new ArgumentException("Username contains invalid characters", 
                nameof(username));
        return username;
    }
    
    private static string ValidateEmail(string email)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(email);
        if (!new EmailAddressAttribute().IsValid(email))
            throw new ArgumentException("Invalid email format", nameof(email));
        return email;
    }
}
```

#### Collection Expressions with Immutability

```csharp
// Immutable collections prevent unauthorized modification
public static class SecurityRoles
{
    public static readonly ImmutableArray<string> AdminRoles = 
        ["SuperAdmin", "SystemAdmin", "SecurityAdmin"];
    
    public static readonly ImmutableArray<string> AllowedOrigins = 
        ["https://app.example.com", "https://api.example.com"];
}
```

#### Required Members for Security Configuration

```csharp
public class JwtSecurityConfig
{
    public required string Issuer { get; init; }
    public required string Audience { get; init; }
    public required string SecretKey { get; init; }
    public required int TokenExpirationMinutes { get; init; }
    public required int RefreshTokenExpirationDays { get; init; }
    
    // Validation on construction
    public JwtSecurityConfig()
    {
        if (TokenExpirationMinutes <= 0 || TokenExpirationMinutes > 60)
            throw new ArgumentOutOfRangeException(nameof(TokenExpirationMinutes),
                "Token expiration must be 1-60 minutes");
    }
}
```

### 2. .NET 8 Security Enhancements

#### Native AOT Security Benefits

```csharp
// Program.cs - Native AOT reduces attack surface
var builder = WebApplication.CreateSlimBuilder(args);

// Minimal APIs with security
builder.Services.AddAuthentication()
    .AddJwtBearer();
builder.Services.AddAuthorization();

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();

// Type-safe route handlers
app.MapGet("/api/secure", [Authorize] (ClaimsPrincipal user) => 
    Results.Ok($"Hello {user.Identity?.Name}"));

app.Run();
```

#### Keyed Services for Secure Dependency Injection

```csharp
// Register keyed cryptographic services
builder.Services.AddKeyedSingleton<ICryptoService, AesCryptoService>("aes");
builder.Services.AddKeyedSingleton<ICryptoService, RsaCryptoService>("rsa");

// Inject specific implementation
public class SecureDataService(
    [FromKeyedServices("aes")] ICryptoService aesCrypto,
    [FromKeyedServices("rsa")] ICryptoService rsaCrypto)
{
    public byte[] EncryptData(byte[] data) => aesCrypto.Encrypt(data);
    public byte[] EncryptKey(byte[] key) => rsaCrypto.Encrypt(key);
}
```

#### TimeProvider for Secure Token Validation

```csharp
public class SecureTokenValidator(TimeProvider timeProvider)
{
    public bool IsTokenValid(SecurityToken token)
    {
        var now = timeProvider.GetUtcNow();
        return token.ValidFrom <= now && token.ValidTo >= now;
    }
    
    public DateTimeOffset GetTokenExpiration(int minutesFromNow)
    {
        return timeProvider.GetUtcNow().AddMinutes(minutesFromNow);
    }
}
```

### 3. Security-Critical API Changes

| Feature | Security Benefit | .NET 8 API |
|---------|-----------------|------------|
| Frozen Collections | Immutable, thread-safe | `FrozenDictionary<K,V>` |
| SearchValues | Safe string matching | `SearchValues.Create()` |
| UTF8 String Literals | Prevents encoding attacks | `"text"u8` |
| Source Generators | Compile-time validation | `[JsonSerializable]` |
| Randomness APIs | Cryptographically secure | `Random.Shared` (with `RandomNumberGenerator` for crypto) |

---

## Secure Coding in ASP.NET Core

### 1. Security Middleware Configuration

```csharp
var builder = WebApplication.CreateBuilder(args);

// Security Services
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = builder.Configuration["Jwt:Issuer"],
            ValidAudience = builder.Configuration["Jwt:Audience"],
            IssuerSigningKey = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(builder.Configuration["Jwt:SecretKey"]!)),
            ClockSkew = TimeSpan.FromMinutes(1) // Reduce clock skew
        };
    });

builder.Services.AddAuthorization(options =>
{
    options.FallbackPolicy = new AuthorizationPolicyBuilder()
        .RequireAuthenticatedUser()
        .Build();
    
    options.AddPolicy("AdminOnly", policy =>
        policy.RequireRole("Admin").RequireClaim("department", "IT"));
});

// Rate Limiting
builder.Services.AddRateLimiter(options =>
{
    options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(
        httpContext => RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: httpContext.User.Identity?.Name 
                ?? httpContext.Connection.RemoteIpAddress?.ToString() 
                ?? "anonymous",
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 100,
                Window = TimeSpan.FromMinutes(1),
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                QueueLimit = 10
            }));
    
    options.OnRejected = async (context, cancellationToken) =>
    {
        context.HttpContext.Response.StatusCode = StatusCodes.Status429TooManyRequests;
        await context.HttpContext.Response.WriteAsJsonAsync(
            new { error = "Rate limit exceeded. Please try again later." },
            cancellationToken);
    };
});

// CORS with strict configuration
builder.Services.AddCors(options =>
{
    options.AddPolicy("SecurePolicy", policy =>
    {
        policy.WithOrigins("https://trusted-domain.com")
              .WithMethods("GET", "POST", "PUT", "DELETE")
              .WithHeaders("Authorization", "Content-Type")
              .SetPreflightMaxAge(TimeSpan.FromMinutes(10));
    });
});

var app = builder.Build();

// Security Middleware Pipeline (ORDER MATTERS!)
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseSecurityHeaders(); // Custom middleware
app.UseCors("SecurePolicy");
app.UseAuthentication();
app.UseAuthorization();
app.UseRateLimiter();

app.Run();
```

### 2. Security Headers Middleware

```csharp
public class SecurityHeadersMiddleware(RequestDelegate next)
{
    public async Task InvokeAsync(HttpContext context)
    {
        // Prevent clickjacking
        context.Response.Headers.Append("X-Frame-Options", "DENY");
        
        // Prevent MIME sniffing
        context.Response.Headers.Append("X-Content-Type-Options", "nosniff");
        
        // XSS Protection
        context.Response.Headers.Append("X-XSS-Protection", "1; mode=block");
        
        // Referrer Policy
        context.Response.Headers.Append("Referrer-Policy", "strict-origin-when-cross-origin");
        
        // Content Security Policy
        context.Response.Headers.Append("Content-Security-Policy",
            "default-src 'self'; " +
            "script-src 'self' 'unsafe-inline'; " +
            "style-src 'self' 'unsafe-inline'; " +
            "img-src 'self' data: https:; " +
            "font-src 'self'; " +
            "frame-ancestors 'none'; " +
            "form-action 'self';");
        
        // Permissions Policy
        context.Response.Headers.Append("Permissions-Policy",
            "accelerometer=(), camera=(), geolocation=(), gyroscope=(), " +
            "magnetometer=(), microphone=(), payment=(), usb=()");
        
        // Strict Transport Security (HSTS)
        if (context.Request.IsHttps)
        {
            context.Response.Headers.Append("Strict-Transport-Security",
                "max-age=31536000; includeSubDomains; preload");
        }
        
        await next(context);
    }
}

public static class SecurityHeadersMiddlewareExtensions
{
    public static IApplicationBuilder UseSecurityHeaders(this IApplicationBuilder builder)
        => builder.UseMiddleware<SecurityHeadersMiddleware>();
}
```

### 3. Secure Configuration Management

```csharp
// Use Secret Manager in development
// dotnet user-secrets set "Database:ConnectionString" "Server=..."

// Use Azure Key Vault or AWS Secrets Manager in production
builder.Configuration
    .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
    .AddJsonFile($"appsettings.{builder.Environment.EnvironmentName}.json", 
        optional: true, reloadOnChange: true)
    .AddEnvironmentVariables()
    .AddUserSecrets<Program>(optional: true);

if (builder.Environment.IsProduction())
{
    builder.Configuration.AddAzureKeyVault(
        new Uri($"https://{builder.Configuration["KeyVaultName"]}.vault.azure.net/"),
        new DefaultAzureCredential());
}

// Validate configuration at startup
builder.Services.AddOptions<JwtSettings>()
    .BindConfiguration("Jwt")
    .ValidateDataAnnotations()
    .ValidateOnStart();

public class JwtSettings
{
    [Required, MinLength(32)]
    public string SecretKey { get; set; } = string.Empty;
    
    [Required, Url]
    public string Issuer { get; set; } = string.Empty;
    
    [Required]
    public string Audience { get; set; } = string.Empty;
    
    [Range(1, 60)]
    public int TokenExpirationMinutes { get; set; } = 15;
}
```

---

## Input Validation and Sanitization

### 1. Data Annotation Validation

```csharp
public class UserRegistrationDto
{
    [Required(ErrorMessage = "Username is required")]
    [StringLength(50, MinimumLength = 3, 
        ErrorMessage = "Username must be 3-50 characters")]
    [RegularExpression(@"^[a-zA-Z0-9_]+$", 
        ErrorMessage = "Username can only contain letters, numbers, and underscores")]
    public string Username { get; set; } = string.Empty;
    
    [Required(ErrorMessage = "Email is required")]
    [EmailAddress(ErrorMessage = "Invalid email format")]
    [MaxLength(255)]
    public string Email { get; set; } = string.Empty;
    
    [Required(ErrorMessage = "Password is required")]
    [StringLength(128, MinimumLength = 12, 
        ErrorMessage = "Password must be 12-128 characters")]
    [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]+$",
        ErrorMessage = "Password must contain uppercase, lowercase, number, and special character")]
    [DataType(DataType.Password)]
    public string Password { get; set; } = string.Empty;
    
    [Compare("Password", ErrorMessage = "Passwords do not match")]
    [DataType(DataType.Password)]
    public string ConfirmPassword { get; set; } = string.Empty;
    
    [Phone(ErrorMessage = "Invalid phone number")]
    public string? PhoneNumber { get; set; }
    
    [Range(18, 120, ErrorMessage = "Age must be between 18 and 120")]
    public int? Age { get; set; }
}
```

### 2. Custom Validation Attributes

```csharp
public class NoSqlInjectionAttribute : ValidationAttribute
{
    private static readonly string[] DangerousPatterns = 
    [
        "'", "\"", "--", ";", "/*", "*/", "xp_", "sp_", 
        "DROP", "DELETE", "INSERT", "UPDATE", "EXEC", "EXECUTE",
        "UNION", "SELECT", "CREATE", "ALTER", "TRUNCATE"
    ];
    
    protected override ValidationResult? IsValid(object? value, 
        ValidationContext validationContext)
    {
        if (value is not string stringValue)
            return ValidationResult.Success;
        
        var upperValue = stringValue.ToUpperInvariant();
        
        foreach (var pattern in DangerousPatterns)
        {
            if (upperValue.Contains(pattern.ToUpperInvariant()))
            {
                return new ValidationResult(
                    $"Input contains potentially dangerous content: {pattern}");
            }
        }
        
        return ValidationResult.Success;
    }
}

public class SafeHtmlAttribute : ValidationAttribute
{
    private static readonly string[] DangerousTags = 
        ["script", "iframe", "object", "embed", "form", "input", "button"];
    
    private static readonly string[] DangerousAttributes = 
        ["onclick", "onerror", "onload", "onmouseover", "onfocus", "onblur"];
    
    protected override ValidationResult? IsValid(object? value, 
        ValidationContext validationContext)
    {
        if (value is not string html)
            return ValidationResult.Success;
        
        var lowerHtml = html.ToLowerInvariant();
        
        foreach (var tag in DangerousTags)
        {
            if (lowerHtml.Contains($"<{tag}") || lowerHtml.Contains($"</{tag}"))
                return new ValidationResult($"HTML contains dangerous tag: {tag}");
        }
        
        foreach (var attr in DangerousAttributes)
        {
            if (lowerHtml.Contains(attr))
                return new ValidationResult($"HTML contains dangerous attribute: {attr}");
        }
        
        return ValidationResult.Success;
    }
}
```

### 3. Input Sanitization Service

```csharp
public interface IInputSanitizer
{
    string SanitizeHtml(string input);
    string SanitizeSql(string input);
    string SanitizeFileName(string input);
    string SanitizeUrl(string input);
}

public class InputSanitizer : IInputSanitizer
{
    private static readonly Regex HtmlTagRegex = new(@"<[^>]*>", RegexOptions.Compiled);
    private static readonly Regex SqlInjectionRegex = new(
        @"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE|UNION|'|""|--))\b",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);
    private static readonly Regex InvalidFileNameChars = new(
        $"[{Regex.Escape(new string(Path.GetInvalidFileNameChars()))}]",
        RegexOptions.Compiled);
    
    public string SanitizeHtml(string input)
    {
        if (string.IsNullOrWhiteSpace(input))
            return string.Empty;
        
        // Remove all HTML tags
        var sanitized = HtmlTagRegex.Replace(input, string.Empty);
        
        // Encode special characters
        sanitized = WebUtility.HtmlEncode(sanitized);
        
        return sanitized.Trim();
    }
    
    public string SanitizeSql(string input)
    {
        if (string.IsNullOrWhiteSpace(input))
            return string.Empty;
        
        // Remove SQL injection patterns
        var sanitized = SqlInjectionRegex.Replace(input, string.Empty);
        
        // Escape single quotes
        sanitized = sanitized.Replace("'", "''");
        
        return sanitized.Trim();
    }
    
    public string SanitizeFileName(string input)
    {
        if (string.IsNullOrWhiteSpace(input))
            return "unnamed";
        
        // Remove invalid characters
        var sanitized = InvalidFileNameChars.Replace(input, "_");
        
        // Prevent directory traversal
        sanitized = sanitized.Replace("..", "_");
        
        // Limit length
        if (sanitized.Length > 255)
            sanitized = sanitized[..255];
        
        return sanitized.Trim();
    }
    
    public string SanitizeUrl(string input)
    {
        if (string.IsNullOrWhiteSpace(input))
            return string.Empty;
        
        // Validate URL format
        if (!Uri.TryCreate(input, UriKind.Absolute, out var uri))
            return string.Empty;
        
        // Only allow HTTP/HTTPS
        if (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps)
            return string.Empty;
        
        return uri.ToString();
    }
}
```

### 4. Anti-Forgery Protection

```csharp
// Program.cs
builder.Services.AddAntiforgery(options =>
{
    options.HeaderName = "X-CSRF-TOKEN";
    options.Cookie.Name = "CSRF-TOKEN";
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Strict;
});

// Controller
[ApiController]
[Route("api/[controller]")]
[ValidateAntiForgeryToken]
public class SecureDataController : ControllerBase
{
    [HttpPost]
    public IActionResult CreateData([FromBody] DataDto data)
    {
        // Process data
        return Ok();
    }
}

// Razor Page
@inject IAntiforgery Antiforgery
@{
    var token = Antiforgery.GetAndStoreTokens(HttpContext);
}
<input type="hidden" name="@token.FormFieldName" value="@token.RequestToken" />
```

---

## Authentication and Authorization

### 1. ASP.NET Core Identity Configuration

```csharp
builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{
    // Password Requirements (NIST SP 800-63B compliant)
    options.Password.RequiredLength = 12;
    options.Password.RequireDigit = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireUppercase = true;
    options.Password.RequireNonAlphanumeric = true;
    options.Password.RequiredUniqueChars = 4;
    
    // Lockout Settings (DISA STIG compliant)
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
    options.Lockout.MaxFailedAccessAttempts = 3;
    options.Lockout.AllowedForNewUsers = true;
    
    // User Settings
    options.User.RequireUniqueEmail = true;
    options.User.AllowedUserNameCharacters = 
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+";
    
    // Sign-in Settings
    options.SignIn.RequireConfirmedEmail = true;
    options.SignIn.RequireConfirmedAccount = true;
})
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddDefaultTokenProviders()
.AddTokenProvider<DataProtectorTokenProvider<ApplicationUser>>("Default");

// Configure token lifespan
builder.Services.Configure<DataProtectionTokenProviderOptions>(options =>
{
    options.TokenLifespan = TimeSpan.FromHours(2);
});
```

### 2. JWT Authentication Implementation

```csharp
public interface IJwtService
{
    string GenerateAccessToken(ApplicationUser user, IList<string> roles);
    RefreshToken GenerateRefreshToken();
    ClaimsPrincipal? GetPrincipalFromExpiredToken(string token);
}

public class JwtService : IJwtService
{
    private readonly JwtSettings _jwtSettings;
    private readonly TimeProvider _timeProvider;
    
    public JwtService(IOptions<JwtSettings> jwtSettings, TimeProvider timeProvider)
    {
        _jwtSettings = jwtSettings.Value;
        _timeProvider = timeProvider;
    }
    
    public string GenerateAccessToken(ApplicationUser user, IList<string> roles)
    {
        var securityKey = new SymmetricSecurityKey(
            Encoding.UTF8.GetBytes(_jwtSettings.SecretKey));
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
        
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, user.Id),
            new(JwtRegisteredClaimNames.Email, user.Email!),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new(JwtRegisteredClaimNames.Iat, 
                _timeProvider.GetUtcNow().ToUnixTimeSeconds().ToString(), 
                ClaimValueTypes.Integer64),
            new(ClaimTypes.Name, user.UserName!),
            new("security_stamp", user.SecurityStamp!)
        };
        
        claims.AddRange(roles.Select(role => new Claim(ClaimTypes.Role, role)));
        
        var token = new JwtSecurityToken(
            issuer: _jwtSettings.Issuer,
            audience: _jwtSettings.Audience,
            claims: claims,
            notBefore: _timeProvider.GetUtcNow().DateTime,
            expires: _timeProvider.GetUtcNow()
                .AddMinutes(_jwtSettings.TokenExpirationMinutes).DateTime,
            signingCredentials: credentials);
        
        return new JwtSecurityTokenHandler().WriteToken(token);
    }
    
    public RefreshToken GenerateRefreshToken()
    {
        var randomBytes = new byte[64];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomBytes);
        
        return new RefreshToken
        {
            Token = Convert.ToBase64String(randomBytes),
            ExpiresAt = _timeProvider.GetUtcNow()
                .AddDays(_jwtSettings.RefreshTokenExpirationDays),
            CreatedAt = _timeProvider.GetUtcNow()
        };
    }
    
    public ClaimsPrincipal? GetPrincipalFromExpiredToken(string token)
    {
        var tokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateIssuerSigningKey = true,
            ValidateLifetime = false, // Allow expired tokens
            ValidIssuer = _jwtSettings.Issuer,
            ValidAudience = _jwtSettings.Audience,
            IssuerSigningKey = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(_jwtSettings.SecretKey))
        };
        
        var tokenHandler = new JwtSecurityTokenHandler();
        
        try
        {
            var principal = tokenHandler.ValidateToken(token, 
                tokenValidationParameters, out var securityToken);
            
            if (securityToken is not JwtSecurityToken jwtSecurityToken ||
                !jwtSecurityToken.Header.Alg.Equals(
                    SecurityAlgorithms.HmacSha256, 
                    StringComparison.InvariantCultureIgnoreCase))
            {
                return null;
            }
            
            return principal;
        }
        catch
        {
            return null;
        }
    }
}
```

### 3. Policy-Based Authorization

```csharp
// Custom Authorization Requirements
public class MinimumAgeRequirement(int minimumAge) : IAuthorizationRequirement
{
    public int MinimumAge { get; } = minimumAge;
}

public class MinimumAgeHandler : AuthorizationHandler<MinimumAgeRequirement>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        MinimumAgeRequirement requirement)
    {
        var dateOfBirthClaim = context.User.FindFirst(c => c.Type == "DateOfBirth");
        
        if (dateOfBirthClaim is null)
            return Task.CompletedTask;
        
        if (DateTime.TryParse(dateOfBirthClaim.Value, out var dateOfBirth))
        {
            var age = DateTime.Today.Year - dateOfBirth.Year;
            if (dateOfBirth > DateTime.Today.AddYears(-age))
                age--;
            
            if (age >= requirement.MinimumAge)
                context.Succeed(requirement);
        }
        
        return Task.CompletedTask;
    }
}

// Resource-Based Authorization
public class DocumentAuthorizationHandler : 
    AuthorizationHandler<OperationAuthorizationRequirement, Document>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        OperationAuthorizationRequirement requirement,
        Document resource)
    {
        if (requirement.Name == Operations.Read)
        {
            if (resource.IsPublic || 
                resource.OwnerId == context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value)
            {
                context.Succeed(requirement);
            }
        }
        else if (requirement.Name == Operations.Update || 
                 requirement.Name == Operations.Delete)
        {
            if (resource.OwnerId == context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value ||
                context.User.IsInRole("Admin"))
            {
                context.Succeed(requirement);
            }
        }
        
        return Task.CompletedTask;
    }
}

// Register policies
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AtLeast21", policy =>
        policy.Requirements.Add(new MinimumAgeRequirement(21)));
    
    options.AddPolicy("CanAccessConfidential", policy =>
        policy.RequireClaim("ClearanceLevel", "Secret", "TopSecret")
              .RequireRole("SecurityOfficer"));
    
    options.AddPolicy("MustBeOwnerOrAdmin", policy =>
        policy.RequireAssertion(context =>
            context.User.HasClaim(c => c.Type == "OwnerId") ||
            context.User.IsInRole("Admin")));
});

builder.Services.AddSingleton<IAuthorizationHandler, MinimumAgeHandler>();
builder.Services.AddSingleton<IAuthorizationHandler, DocumentAuthorizationHandler>();
```

### 4. Multi-Factor Authentication

```csharp
public class MfaService(
    UserManager<ApplicationUser> userManager,
    IEmailSender emailSender,
    TimeProvider timeProvider)
{
    public async Task<string> GenerateTotpSecretAsync(ApplicationUser user)
    {
        var secret = Base32Encoding.ToString(
            RandomNumberGenerator.GetBytes(20));
        
        user.TotpSecret = secret;
        await userManager.UpdateAsync(user);
        
        return secret;
    }
    
    public string GenerateQrCodeUri(ApplicationUser user, string secret)
    {
        var issuer = Uri.EscapeDataString("MySecureApp");
        var account = Uri.EscapeDataString(user.Email!);
        
        return $"otpauth://totp/{issuer}:{account}?secret={secret}&issuer={issuer}&digits=6&period=30";
    }
    
    public bool ValidateTotpCode(ApplicationUser user, string code)
    {
        if (string.IsNullOrWhiteSpace(user.TotpSecret))
            return false;
        
        var secretBytes = Base32Encoding.ToBytes(user.TotpSecret);
        var totp = new Totp(secretBytes, step: 30);
        
        // Allow 1 step before and after for clock drift
        return totp.VerifyTotp(code, out _, new VerificationWindow(1, 1));
    }
    
    public async Task<string> GenerateEmailCodeAsync(ApplicationUser user)
    {
        var code = RandomNumberGenerator.GetInt32(100000, 999999).ToString();
        
        user.EmailMfaCode = code;
        user.EmailMfaCodeExpiry = timeProvider.GetUtcNow().AddMinutes(10);
        await userManager.UpdateAsync(user);
        
        await emailSender.SendEmailAsync(
            user.Email!,
            "Your Verification Code",
            $"Your verification code is: {code}. This code expires in 10 minutes.");
        
        return code;
    }
}
```

---

## Entity Framework Security

### 1. Secure DbContext Configuration

```csharp
public class SecureApplicationDbContext : DbContext
{
    private readonly ICurrentUserService _currentUserService;
    private readonly TimeProvider _timeProvider;
    
    public SecureApplicationDbContext(
        DbContextOptions<SecureApplicationDbContext> options,
        ICurrentUserService currentUserService,
        TimeProvider timeProvider) : base(options)
    {
        _currentUserService = currentUserService;
        _timeProvider = timeProvider;
    }
    
    public DbSet<User> Users => Set<User>();
    public DbSet<AuditLog> AuditLogs => Set<AuditLog>();
    
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);
        
        // Global query filter for soft delete
        modelBuilder.Entity<User>()
            .HasQueryFilter(u => !u.IsDeleted);
        
        // Encrypt sensitive columns
        modelBuilder.Entity<User>()
            .Property(u => u.SocialSecurityNumber)
            .HasConversion(
                v => EncryptionHelper.Encrypt(v),
                v => EncryptionHelper.Decrypt(v));
        
        // Row-level security via query filter
        modelBuilder.Entity<Document>()
            .HasQueryFilter(d => 
                d.OwnerId == _currentUserService.UserId ||
                d.IsPublic ||
                _currentUserService.IsAdmin);
    }
    
    public override async Task<int> SaveChangesAsync(
        CancellationToken cancellationToken = default)
    {
        var auditEntries = OnBeforeSaveChanges();
        var result = await base.SaveChangesAsync(cancellationToken);
        await OnAfterSaveChanges(auditEntries, cancellationToken);
        return result;
    }
    
    private List<AuditEntry> OnBeforeSaveChanges()
    {
        ChangeTracker.DetectChanges();
        var auditEntries = new List<AuditEntry>();
        var now = _timeProvider.GetUtcNow();
        
        foreach (var entry in ChangeTracker.Entries())
        {
            if (entry.Entity is AuditLog || entry.State == EntityState.Detached ||
                entry.State == EntityState.Unchanged)
                continue;
            
            // Set audit fields
            if (entry.Entity is IAuditableEntity auditableEntity)
            {
                switch (entry.State)
                {
                    case EntityState.Added:
                        auditableEntity.CreatedAt = now;
                        auditableEntity.CreatedBy = _currentUserService.UserId;
                        break;
                    case EntityState.Modified:
                        auditableEntity.ModifiedAt = now;
                        auditableEntity.ModifiedBy = _currentUserService.UserId;
                        break;
                }
            }
            
            // Create audit log entry
            var auditEntry = new AuditEntry(entry)
            {
                TableName = entry.Entity.GetType().Name,
                UserId = _currentUserService.UserId,
                Action = entry.State.ToString(),
                Timestamp = now
            };
            
            foreach (var property in entry.Properties)
            {
                if (property.IsTemporary)
                {
                    auditEntry.TemporaryProperties.Add(property);
                    continue;
                }
                
                var propertyName = property.Metadata.Name;
                
                if (property.Metadata.IsPrimaryKey())
                {
                    auditEntry.KeyValues[propertyName] = property.CurrentValue;
                    continue;
                }
                
                switch (entry.State)
                {
                    case EntityState.Added:
                        auditEntry.NewValues[propertyName] = property.CurrentValue;
                        break;
                    case EntityState.Deleted:
                        auditEntry.OldValues[propertyName] = property.OriginalValue;
                        break;
                    case EntityState.Modified when property.IsModified:
                        auditEntry.OldValues[propertyName] = property.OriginalValue;
                        auditEntry.NewValues[propertyName] = property.CurrentValue;
                        break;
                }
            }
            
            auditEntries.Add(auditEntry);
        }
        
        return auditEntries;
    }
    
    private async Task OnAfterSaveChanges(List<AuditEntry> auditEntries, 
        CancellationToken cancellationToken)
    {
        if (auditEntries.Count == 0)
            return;
        
        foreach (var auditEntry in auditEntries)
        {
            foreach (var prop in auditEntry.TemporaryProperties)
            {
                if (prop.Metadata.IsPrimaryKey())
                    auditEntry.KeyValues[prop.Metadata.Name] = prop.CurrentValue;
                else
                    auditEntry.NewValues[prop.Metadata.Name] = prop.CurrentValue;
            }
            
            AuditLogs.Add(auditEntry.ToAuditLog());
        }
        
        await base.SaveChangesAsync(cancellationToken);
    }
}
```

### 2. Parameterized Queries (SQL Injection Prevention)

```csharp
public class UserRepository(SecureApplicationDbContext context)
{
    // SAFE: Using LINQ - parameterized automatically
    public async Task<User?> GetByEmailAsync(string email)
    {
        return await context.Users
            .FirstOrDefaultAsync(u => u.Email == email);
    }
    
    // SAFE: Using parameterized FromSqlInterpolated
    public async Task<List<User>> SearchUsersAsync(string searchTerm)
    {
        return await context.Users
            .FromSqlInterpolated(
                $"SELECT * FROM Users WHERE Name LIKE {'%' + searchTerm + '%'}")
            .ToListAsync();
    }
    
    // SAFE: Using parameterized raw SQL
    public async Task<List<User>> GetUsersByRoleAsync(string role)
    {
        return await context.Users
            .FromSqlRaw(
                "SELECT u.* FROM Users u " +
                "INNER JOIN UserRoles ur ON u.Id = ur.UserId " +
                "INNER JOIN Roles r ON ur.RoleId = r.Id " +
                "WHERE r.Name = {0}", role)
            .ToListAsync();
    }
    
    // SAFE: Using ExecuteSqlInterpolatedAsync for updates
    public async Task<int> DeactivateUserAsync(string userId)
    {
        return await context.Database.ExecuteSqlInterpolatedAsync(
            $"UPDATE Users SET IsActive = 0 WHERE Id = {userId}");
    }
    
    // DANGEROUS - DO NOT USE: String concatenation
    // public async Task<User?> UnsafeGetByEmail(string email)
    // {
    //     return await context.Users
    //         .FromSqlRaw($"SELECT * FROM Users WHERE Email = '{email}'")
    //         .FirstOrDefaultAsync();
    // }
}
```

### 3. Connection String Security

```csharp
// appsettings.json - Development (use User Secrets instead)
{
    "ConnectionStrings": {
        // NEVER store actual credentials in appsettings.json
        "DefaultConnection": "Server=localhost;Database=MyApp;Integrated Security=true;Encrypt=true;TrustServerCertificate=false"
    }
}

// Program.cs - Production configuration
builder.Services.AddDbContext<ApplicationDbContext>((services, options) =>
{
    var configuration = services.GetRequiredService<IConfiguration>();
    
    // Use Managed Identity in Azure
    if (builder.Environment.IsProduction())
    {
        var connectionString = configuration.GetConnectionString("DefaultConnection");
        options.UseSqlServer(connectionString, sqlOptions =>
        {
            sqlOptions.EnableRetryOnFailure(
                maxRetryCount: 5,
                maxRetryDelay: TimeSpan.FromSeconds(30),
                errorNumbersToAdd: null);
            sqlOptions.CommandTimeout(30);
        });
    }
    else
    {
        options.UseSqlServer(configuration.GetConnectionString("DefaultConnection"));
    }
    
    // Disable sensitive data logging in production
    if (!builder.Environment.IsDevelopment())
    {
        options.EnableSensitiveDataLogging(false);
    }
});

// Azure Managed Identity connection string
// Server=myserver.database.windows.net;Database=MyApp;Authentication=Active Directory Managed Identity;Encrypt=true
```

---

## Cryptography with System.Security.Cryptography

### 1. Symmetric Encryption (AES-256-GCM)

```csharp
public interface IEncryptionService
{
    byte[] Encrypt(byte[] plaintext, byte[] key);
    byte[] Decrypt(byte[] ciphertext, byte[] key);
    string EncryptString(string plaintext, string base64Key);
    string DecryptString(string ciphertext, string base64Key);
}

public class AesGcmEncryptionService : IEncryptionService
{
    private const int NonceSize = 12; // 96 bits for GCM
    private const int TagSize = 16;   // 128 bits for authentication tag
    private const int KeySize = 32;   // 256 bits for AES-256
    
    public byte[] Encrypt(byte[] plaintext, byte[] key)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        ArgumentNullException.ThrowIfNull(key);
        
        if (key.Length != KeySize)
            throw new ArgumentException($"Key must be {KeySize} bytes", nameof(key));
        
        var nonce = new byte[NonceSize];
        RandomNumberGenerator.Fill(nonce);
        
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[TagSize];
        
        using var aesGcm = new AesGcm(key, TagSize);
        aesGcm.Encrypt(nonce, plaintext, ciphertext, tag);
        
        // Combine: nonce + ciphertext + tag
        var result = new byte[NonceSize + ciphertext.Length + TagSize];
        Buffer.BlockCopy(nonce, 0, result, 0, NonceSize);
        Buffer.BlockCopy(ciphertext, 0, result, NonceSize, ciphertext.Length);
        Buffer.BlockCopy(tag, 0, result, NonceSize + ciphertext.Length, TagSize);
        
        return result;
    }
    
    public byte[] Decrypt(byte[] encryptedData, byte[] key)
    {
        ArgumentNullException.ThrowIfNull(encryptedData);
        ArgumentNullException.ThrowIfNull(key);
        
        if (key.Length != KeySize)
            throw new ArgumentException($"Key must be {KeySize} bytes", nameof(key));
        
        if (encryptedData.Length < NonceSize + TagSize)
            throw new ArgumentException("Invalid encrypted data", nameof(encryptedData));
        
        var nonce = new byte[NonceSize];
        var ciphertextLength = encryptedData.Length - NonceSize - TagSize;
        var ciphertext = new byte[ciphertextLength];
        var tag = new byte[TagSize];
        
        Buffer.BlockCopy(encryptedData, 0, nonce, 0, NonceSize);
        Buffer.BlockCopy(encryptedData, NonceSize, ciphertext, 0, ciphertextLength);
        Buffer.BlockCopy(encryptedData, NonceSize + ciphertextLength, tag, 0, TagSize);
        
        var plaintext = new byte[ciphertextLength];
        
        using var aesGcm = new AesGcm(key, TagSize);
        aesGcm.Decrypt(nonce, ciphertext, tag, plaintext);
        
        return plaintext;
    }
    
    public string EncryptString(string plaintext, string base64Key)
    {
        var key = Convert.FromBase64String(base64Key);
        var plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
        var encrypted = Encrypt(plaintextBytes, key);
        return Convert.ToBase64String(encrypted);
    }
    
    public string DecryptString(string ciphertext, string base64Key)
    {
        var key = Convert.FromBase64String(base64Key);
        var encryptedBytes = Convert.FromBase64String(ciphertext);
        var decrypted = Decrypt(encryptedBytes, key);
        return Encoding.UTF8.GetString(decrypted);
    }
    
    public static byte[] GenerateKey()
    {
        var key = new byte[KeySize];
        RandomNumberGenerator.Fill(key);
        return key;
    }
}
```

### 2. Asymmetric Encryption (RSA)

```csharp
public interface IRsaEncryptionService
{
    (string PublicKey, string PrivateKey) GenerateKeyPair(int keySize = 4096);
    byte[] Encrypt(byte[] data, string publicKeyPem);
    byte[] Decrypt(byte[] encryptedData, string privateKeyPem);
    byte[] Sign(byte[] data, string privateKeyPem);
    bool Verify(byte[] data, byte[] signature, string publicKeyPem);
}

public class RsaEncryptionService : IRsaEncryptionService
{
    public (string PublicKey, string PrivateKey) GenerateKeyPair(int keySize = 4096)
    {
        using var rsa = RSA.Create(keySize);
        
        var privateKey = rsa.ExportRSAPrivateKeyPem();
        var publicKey = rsa.ExportRSAPublicKeyPem();
        
        return (publicKey, privateKey);
    }
    
    public byte[] Encrypt(byte[] data, string publicKeyPem)
    {
        using var rsa = RSA.Create();
        rsa.ImportFromPem(publicKeyPem);
        
        return rsa.Encrypt(data, RSAEncryptionPadding.OaepSHA256);
    }
    
    public byte[] Decrypt(byte[] encryptedData, string privateKeyPem)
    {
        using var rsa = RSA.Create();
        rsa.ImportFromPem(privateKeyPem);
        
        return rsa.Decrypt(encryptedData, RSAEncryptionPadding.OaepSHA256);
    }
    
    public byte[] Sign(byte[] data, string privateKeyPem)
    {
        using var rsa = RSA.Create();
        rsa.ImportFromPem(privateKeyPem);
        
        return rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
    }
    
    public bool Verify(byte[] data, byte[] signature, string publicKeyPem)
    {
        using var rsa = RSA.Create();
        rsa.ImportFromPem(publicKeyPem);
        
        return rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
    }
}
```

### 3. Password Hashing (Argon2id / PBKDF2)

```csharp
public interface IPasswordHasher
{
    string HashPassword(string password);
    bool VerifyPassword(string password, string hash);
}

// Argon2id Implementation (Preferred for new applications)
public class Argon2PasswordHasher : IPasswordHasher
{
    private const int SaltSize = 16;
    private const int HashSize = 32;
    private const int Iterations = 4;
    private const int MemorySize = 65536; // 64 MB
    private const int DegreeOfParallelism = 4;
    
    public string HashPassword(string password)
    {
        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        
        var argon2 = new Argon2id(Encoding.UTF8.GetBytes(password))
        {
            Salt = salt,
            Iterations = Iterations,
            MemorySize = MemorySize,
            DegreeOfParallelism = DegreeOfParallelism
        };
        
        var hash = argon2.GetBytes(HashSize);
        
        // Format: $argon2id$v=19$m=65536,t=4,p=4$<salt>$<hash>
        return $"$argon2id$v=19$m={MemorySize},t={Iterations},p={DegreeOfParallelism}$" +
               $"{Convert.ToBase64String(salt)}${Convert.ToBase64String(hash)}";
    }
    
    public bool VerifyPassword(string password, string hash)
    {
        try
        {
            var parts = hash.Split('$');
            if (parts.Length != 6 || parts[1] != "argon2id")
                return false;
            
            var salt = Convert.FromBase64String(parts[4]);
            var expectedHash = Convert.FromBase64String(parts[5]);

            var argon2 = new Argon2id(Encoding.UTF8.GetBytes(password))
            {
                Salt = salt,
                Iterations = Iterations,
                MemorySize = MemorySize,
                DegreeOfParallelism = DegreeOfParallelism
            };
            
            var computedHash = argon2.GetBytes(HashSize);
            
            return CryptographicOperations.FixedTimeEquals(computedHash, expectedHash);
        }
        catch
        {
            return false;
        }
    }
}

// PBKDF2 Implementation (FIPS 140-3 compliant)
public class Pbkdf2PasswordHasher : IPasswordHasher
{
    private const int SaltSize = 32;
    private const int HashSize = 32;
    private const int Iterations = 600000; // OWASP recommendation for SHA-256
    
    public string HashPassword(string password)
    {
        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var hash = Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(password),
            salt,
            Iterations,
            HashAlgorithmName.SHA256,
            HashSize);
        
        // Format: iterations:salt:hash
        return $"{Iterations}:{Convert.ToBase64String(salt)}:{Convert.ToBase64String(hash)}";
    }
    
    public bool VerifyPassword(string password, string storedHash)
    {
        try
        {
            var parts = storedHash.Split(':');
            if (parts.Length != 3)
                return false;
            
            var iterations = int.Parse(parts[0]);
            var salt = Convert.FromBase64String(parts[1]);
            var hash = Convert.FromBase64String(parts[2]);
            
            var computedHash = Rfc2898DeriveBytes.Pbkdf2(
                Encoding.UTF8.GetBytes(password),
                salt,
                iterations,
                HashAlgorithmName.SHA256,
                hash.Length);
            
            return CryptographicOperations.FixedTimeEquals(computedHash, hash);
        }
        catch
        {
            return false;
        }
    }
}
```

### 4. Secure Key Management

```csharp
public interface IKeyManagementService
{
    byte[] GetKey(string keyId);
    void RotateKey(string keyId);
    byte[] DeriveKey(byte[] masterKey, string purpose, int keyLength = 32);
}

public class KeyManagementService : IKeyManagementService
{
    private readonly IConfiguration _configuration;
    private readonly IMemoryCache _cache;
    
    public KeyManagementService(IConfiguration configuration, IMemoryCache cache)
    {
        _configuration = configuration;
        _cache = cache;
    }
    
    public byte[] GetKey(string keyId)
    {
        // In production, retrieve from Azure Key Vault, AWS KMS, or HashiCorp Vault
        var keyValue = _configuration[$"Keys:{keyId}"];
        
        if (string.IsNullOrEmpty(keyValue))
            throw new InvalidOperationException($"Key not found: {keyId}");
        
        return Convert.FromBase64String(keyValue);
    }
    
    public void RotateKey(string keyId)
    {
        // Generate new key
        var newKey = RandomNumberGenerator.GetBytes(32);
        
        // Store new key (implementation depends on key storage)
        // In production: Update Azure Key Vault, AWS KMS, etc.
        
        // Invalidate cache
        _cache.Remove($"key:{keyId}");
    }
    
    public byte[] DeriveKey(byte[] masterKey, string purpose, int keyLength = 32)
    {
        // Use HKDF for key derivation
        return HKDF.DeriveKey(
            HashAlgorithmName.SHA256,
            masterKey,
            keyLength,
            info: Encoding.UTF8.GetBytes(purpose));
    }
}

// Data Protection API for ASP.NET Core
public static class DataProtectionConfig
{
    public static void ConfigureDataProtection(
        this IServiceCollection services, 
        IConfiguration configuration,
        IWebHostEnvironment environment)
    {
        var dpBuilder = services.AddDataProtection()
            .SetApplicationName("MySecureApplication");
        
        if (environment.IsProduction())
        {
            // Use Azure Key Vault for key storage
            var keyVaultUri = configuration["Azure:KeyVault:Uri"];
            var keyIdentifier = configuration["Azure:KeyVault:DataProtectionKeyId"];
            
            dpBuilder
                .PersistKeysToAzureBlobStorage(
                    new Uri(configuration["Azure:Storage:DataProtectionContainer"]!))
                .ProtectKeysWithAzureKeyVault(
                    new Uri(keyIdentifier!),
                    new DefaultAzureCredential());
        }
        else
        {
            dpBuilder.PersistKeysToFileSystem(
                new DirectoryInfo(Path.Combine(environment.ContentRootPath, "keys")));
        }
        
        dpBuilder.SetDefaultKeyLifetime(TimeSpan.FromDays(90));
    }
}
```

---

## OWASP Top Ten Mitigations for .NET

### Reference Table: OWASP Top Ten 2021

| # | Vulnerability | .NET Mitigation | Code Reference |
|---|--------------|-----------------|----------------|
| A01 | Broken Access Control | `[Authorize]`, Policy-based auth, Resource-based auth | Section 5.3 |
| A02 | Cryptographic Failures | AES-GCM, RSA-OAEP, PBKDF2/Argon2 | Section 7 |
| A03 | Injection | EF Core LINQ, Parameterized queries | Section 6.2 |
| A04 | Insecure Design | Threat modeling, Security middleware | Section 3 |
| A05 | Security Misconfiguration | HSTS, CSP, Security headers | Section 3.2 |
| A06 | Vulnerable Components | `dotnet list package --vulnerable` | Below |
| A07 | Auth Failures | Identity, JWT, MFA | Section 5 |
| A08 | Data Integrity Failures | HMAC, Digital signatures | Section 7.2 |
| A09 | Logging Failures | Structured logging, SIEM integration | Below |
| A10 | SSRF | URL validation, Whitelist | Below |

### A01: Broken Access Control

```csharp
// Resource-based authorization
[ApiController]
[Route("api/[controller]")]
public class DocumentsController(
    IAuthorizationService authorizationService,
    IDocumentRepository documentRepository) : ControllerBase
{
    [HttpGet("{id}")]
    public async Task<IActionResult> GetDocument(int id)
    {
        var document = await documentRepository.GetByIdAsync(id);
        
        if (document is null)
            return NotFound();
        
        var authResult = await authorizationService.AuthorizeAsync(
            User, document, Operations.Read);
        
        if (!authResult.Succeeded)
            return Forbid();
        
        return Ok(document);
    }
    
    [HttpDelete("{id}")]
    public async Task<IActionResult> DeleteDocument(int id)
    {
        var document = await documentRepository.GetByIdAsync(id);
        
        if (document is null)
            return NotFound();
        
        var authResult = await authorizationService.AuthorizeAsync(
            User, document, Operations.Delete);
        
        if (!authResult.Succeeded)
            return Forbid();
        
        await documentRepository.DeleteAsync(id);
        return NoContent();
    }
}
```

### A06: Vulnerable and Outdated Components

```bash
# Check for vulnerable packages
dotnet list package --vulnerable

# Update all packages
dotnet outdated --upgrade

# Use Dependabot or Renovate for automated updates
```

```xml
<!-- .csproj - Pin versions and enable security analyzers -->
<Project Sdk="Microsoft.NET.Sdk.Web">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
    <TreatWarningsAsErrors>true</TreatWarningsAsErrors>
    <AnalysisMode>AllEnabledByDefault</AnalysisMode>
    <EnableNETAnalyzers>true</EnableNETAnalyzers>
  </PropertyGroup>
  
  <ItemGroup>
    <PackageReference Include="Microsoft.CodeAnalysis.NetAnalyzers" Version="8.*">
      <PrivateAssets>all</PrivateAssets>
      <IncludeAssets>runtime; build; native; contentfiles; analyzers</IncludeAssets>
    </PackageReference>
    <PackageReference Include="SecurityCodeScan.VS2019" Version="5.*">
      <PrivateAssets>all</PrivateAssets>
    </PackageReference>
  </ItemGroup>
</Project>
```

### A09: Security Logging and Monitoring Failures

```csharp
public class SecurityAuditMiddleware(
    RequestDelegate next,
    ILogger<SecurityAuditMiddleware> logger)
{
    public async Task InvokeAsync(HttpContext context)
    {
        var requestId = Activity.Current?.Id ?? context.TraceIdentifier;
        
        // Log request details
        using (logger.BeginScope(new Dictionary<string, object>
        {
            ["RequestId"] = requestId,
            ["UserId"] = context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? "anonymous",
            ["IpAddress"] = context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            ["UserAgent"] = context.Request.Headers.UserAgent.ToString()
        }))
        {
            logger.LogInformation(
                "Security Audit: {Method} {Path} from {IpAddress}",
                context.Request.Method,
                context.Request.Path,
                context.Connection.RemoteIpAddress);
            
            var originalBodyStream = context.Response.Body;
            
            try
            {
                await next(context);
                
                // Log security-relevant responses
                if (context.Response.StatusCode is 401 or 403)
                {
                    logger.LogWarning(
                        "Security Event: Unauthorized access attempt - " +
                        "Status: {StatusCode}, Path: {Path}, User: {User}",
                        context.Response.StatusCode,
                        context.Request.Path,
                        context.User.Identity?.Name ?? "anonymous");
                }
            }
            catch (Exception ex)
            {
                logger.LogError(ex,
                    "Security Exception: {Message} - Path: {Path}",
                    ex.Message,
                    context.Request.Path);
                throw;
            }
        }
    }
}

// Serilog configuration for security logging
Log.Logger = new LoggerConfiguration()
    .MinimumLevel.Information()
    .MinimumLevel.Override("Microsoft", LogEventLevel.Warning)
    .Enrich.FromLogContext()
    .Enrich.WithMachineName()
    .Enrich.WithEnvironmentName()
    .WriteTo.Console(outputTemplate: 
        "[{Timestamp:HH:mm:ss} {Level:u3}] {Message:lj} " +
        "{Properties:j}{NewLine}{Exception}")
    .WriteTo.File(
        path: "logs/security-.log",
        rollingInterval: RollingInterval.Day,
        retainedFileCountLimit: 90,
        outputTemplate: 
            "{Timestamp:yyyy-MM-dd HH:mm:ss.fff} [{Level:u3}] " +
            "{Message:lj} {Properties:j}{NewLine}{Exception}")
    .WriteTo.Seq("http://localhost:5341") // Or Splunk, ELK, Azure Monitor
    .CreateLogger();
```

### A10: Server-Side Request Forgery (SSRF)

```csharp
public class SafeHttpClientService(HttpClient httpClient)
{
    private static readonly HashSet<string> AllowedDomains = new(StringComparer.OrdinalIgnoreCase)
    {
        "api.trusted-service.com",
        "cdn.trusted-service.com",
        "data.trusted-service.com"
    };
    
    private static readonly HashSet<string> BlockedIpRanges = new()
    {
        "10.", "172.16.", "172.17.", "172.18.", "172.19.",
        "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
        "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
        "172.30.", "172.31.", "192.168.", "127.", "0.", "169.254."
    };
    
    public async Task<string> FetchUrlAsync(string url)
    {
        if (!ValidateUrl(url))
            throw new SecurityException("URL validation failed");
        
        return await httpClient.GetStringAsync(url);
    }
    
    private bool ValidateUrl(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            return false;
        
        // Only allow HTTPS
        if (uri.Scheme != Uri.UriSchemeHttps)
            return false;
        
        // Check against whitelist
        if (!AllowedDomains.Contains(uri.Host))
            return false;
        
        // Resolve and check for internal IPs
        try
        {
            var addresses = Dns.GetHostAddresses(uri.Host);
            foreach (var address in addresses)
            {
                var ipString = address.ToString();
                if (BlockedIpRanges.Any(range => ipString.StartsWith(range)))
                    return false;
            }
        }
        catch
        {
            return false;
        }
        
        return true;
    }
}
```

---

## NIST SP 800-53 Compliance

### Relevant Control Families for .NET Applications

| Control Family | Control ID | Requirement | .NET Implementation |
|---------------|------------|-------------|---------------------|
| **Access Control (AC)** | AC-2 | Account Management | ASP.NET Core Identity |
| | AC-3 | Access Enforcement | `[Authorize]` attribute |
| | AC-6 | Least Privilege | Role-based authorization |
| | AC-7 | Unsuccessful Logon Attempts | Identity lockout settings |
| | AC-11 | Session Lock | Session timeout middleware |
| | AC-12 | Session Termination | Token expiration |
| **Audit (AU)** | AU-2 | Audit Events | Serilog/Application Insights |
| | AU-3 | Content of Audit Records | Structured logging |
| | AU-9 | Protection of Audit Info | Log file permissions |
| | AU-12 | Audit Generation | Audit middleware |
| **Identification (IA)** | IA-2 | Identification and Authentication | JWT/Identity |
| | IA-5 | Authenticator Management | Password policies |
| | IA-8 | Identification of Non-Org Users | External auth providers |
| **System Integrity (SI)** | SI-10 | Information Input Validation | Data annotations |
| | SI-11 | Error Handling | Exception middleware |
| | SI-16 | Memory Protection | .NET managed code |
| **System Protection (SC)** | SC-8 | Transmission Confidentiality | HTTPS/TLS |
| | SC-13 | Cryptographic Protection | System.Security.Cryptography |
| | SC-28 | Protection of Information at Rest | AES encryption |

### NIST Compliance Implementation Example

```csharp
// AC-7: Unsuccessful Logon Attempts
builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{
    // Lock account after 3 failed attempts
    options.Lockout.MaxFailedAccessAttempts = 3;
    // Lock for 15 minutes
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
    options.Lockout.AllowedForNewUsers = true;
})
.AddEntityFrameworkStores<ApplicationDbContext>();

// AU-2, AU-3: Audit Events and Content
public class NistAuditService(ILogger<NistAuditService> logger)
{
    public void LogSecurityEvent(
        string eventType,
        string userId,
        string action,
        string resource,
        bool success,
        string? additionalInfo = null)
    {
        // AU-3 content requirements
        logger.LogInformation(
            "SecurityAudit: Type={EventType}, UserId={UserId}, " +
            "Action={Action}, Resource={Resource}, Success={Success}, " +
            "Timestamp={Timestamp}, AdditionalInfo={AdditionalInfo}",
            eventType,
            userId,
            action,
            resource,
            success,
            DateTimeOffset.UtcNow,
            additionalInfo);
    }
}

// SC-13: Cryptographic Protection
public class NistCryptoService
{
    // Use FIPS-approved algorithms only
    public byte[] ComputeHash(byte[] data)
    {
        using var sha256 = SHA256.Create();
        return sha256.ComputeHash(data);
    }
    
    public byte[] Encrypt(byte[] data, byte[] key)
    {
        // AES-256 is FIPS-approved
        using var aes = Aes.Create();
        aes.KeySize = 256;
        aes.Key = key;
        aes.GenerateIV();
        
        using var encryptor = aes.CreateEncryptor();
        var encrypted = encryptor.TransformFinalBlock(data, 0, data.Length);
        
        var result = new byte[aes.IV.Length + encrypted.Length];
        Buffer.BlockCopy(aes.IV, 0, result, 0, aes.IV.Length);
        Buffer.BlockCopy(encrypted, 0, result, aes.IV.Length, encrypted.Length);
        
        return result;
    }
}
```

---

## DISA STIG Requirements

### Application Security and Development STIG (Version 6)

#### Category I (High) Findings - Critical Requirements

| Finding ID | Requirement | .NET Implementation |
|------------|-------------|---------------------|
| V-222602 | Protect from XSS | HTML encoding, CSP headers |
| V-222607 | Protect from SQL Injection | Parameterized queries |
| V-222604 | Protect from Command Injection | Input validation |
| V-222570 | FIPS-validated crypto for signing | RSA with SHA-256 |
| V-222571 | FIPS-validated crypto for hashing | SHA-256, SHA-384, SHA-512 |
| V-222588 | Protect data at rest | AES-256 encryption |
| V-222596 | Protect transmitted information | TLS 1.2+ |

#### Session Management Requirements

```csharp
// V-222389: 15-minute idle timeout for non-privileged users
// V-222390: 10-minute idle timeout for admin users
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(15);
    options.Cookie.HttpOnly = true;      // V-222575
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always; // V-222576
    options.Cookie.SameSite = SameSiteMode.Strict;
    options.Cookie.Name = ".MyApp.Session";
});

// V-222579: System-generated session identifiers
// ASP.NET Core handles this automatically with cryptographically random session IDs

// V-222581: No URL embedded session IDs
// ASP.NET Core uses cookies by default, not URL-based sessions

// V-222583: FIPS 140-2/140-3 approved random number generator
public class FipsCompliantSessionIdGenerator
{
    public string GenerateSessionId()
    {
        var bytes = new byte[32];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(bytes);
        return Convert.ToBase64String(bytes);
    }
}
```

#### Password Requirements Implementation

```csharp
// V-222536: Minimum 15-character password length
// V-222537-V-222540: Complexity requirements
// V-222544: Minimum 24-hour password lifetime
// V-222545: Maximum 60-day password lifetime
// V-222546: 5 generation password reuse prohibition

public class StigPasswordValidator<TUser> : IPasswordValidator<TUser> 
    where TUser : class
{
    public Task<IdentityResult> ValidateAsync(
        UserManager<TUser> manager, 
        TUser user, 
        string? password)
    {
        var errors = new List<IdentityError>();
        
        if (string.IsNullOrEmpty(password))
        {
            errors.Add(new IdentityError 
            { 
                Code = "PasswordRequired", 
                Description = "Password is required" 
            });
            return Task.FromResult(IdentityResult.Failed(errors.ToArray()));
        }
        
        // V-222536: Minimum 15 characters
        if (password.Length < 15)
        {
            errors.Add(new IdentityError
            {
                Code = "PasswordTooShort",
                Description = "Password must be at least 15 characters"
            });
        }
        
        // V-222537: At least one uppercase
        if (!password.Any(char.IsUpper))
        {
            errors.Add(new IdentityError
            {
                Code = "PasswordRequiresUpper",
                Description = "Password must contain at least one uppercase letter"
            });
        }
        
        // V-222538: At least one lowercase
        if (!password.Any(char.IsLower))
        {
            errors.Add(new IdentityError
            {
                Code = "PasswordRequiresLower",
                Description = "Password must contain at least one lowercase letter"
            });
        }
        
        // V-222539: At least one numeric
        if (!password.Any(char.IsDigit))
        {
            errors.Add(new IdentityError
            {
                Code = "PasswordRequiresDigit",
                Description = "Password must contain at least one number"
            });
        }
        
        // V-222540: At least one special character
        if (!password.Any(c => !char.IsLetterOrDigit(c)))
        {
            errors.Add(new IdentityError
            {
                Code = "PasswordRequiresSpecial",
                Description = "Password must contain at least one special character"
            });
        }
        
        return Task.FromResult(errors.Count == 0 
            ? IdentityResult.Success 
            : IdentityResult.Failed(errors.ToArray()));
    }
}

// Password history tracking
public class PasswordHistoryService(ApplicationDbContext context)
{
    private const int HistoryCount = 5; // V-222546
    
    public async Task<bool> IsPasswordInHistoryAsync(string userId, string passwordHash)
    {
        var recentPasswords = await context.PasswordHistories
            .Where(ph => ph.UserId == userId)
            .OrderByDescending(ph => ph.CreatedAt)
            .Take(HistoryCount)
            .ToListAsync();
        
        return recentPasswords.Any(ph => ph.PasswordHash == passwordHash);
    }
    
    public async Task AddToHistoryAsync(string userId, string passwordHash)
    {
        context.PasswordHistories.Add(new PasswordHistory
        {
            UserId = userId,
            PasswordHash = passwordHash,
            CreatedAt = DateTimeOffset.UtcNow
        });
        
        // Remove old entries beyond history limit
        var oldEntries = await context.PasswordHistories
            .Where(ph => ph.UserId == userId)
            .OrderByDescending(ph => ph.CreatedAt)
            .Skip(HistoryCount)
            .ToListAsync();
        
        context.PasswordHistories.RemoveRange(oldEntries);
        await context.SaveChangesAsync();
    }
}
```

#### DoD Banner Requirement

```csharp
// V-222434, V-222435, V-222436: Standard Mandatory DoD Notice and Consent Banner
public class DodBannerMiddleware(RequestDelegate next)
{
    private const string DodBanner = @"
You are accessing a U.S. Government (USG) Information System (IS) that is provided 
for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to 
the following conditions:
- The USG routinely intercepts and monitors communications on this IS for purposes 
  including, but not limited to, penetration testing, COMSEC monitoring, network 
  operations and defense, personnel misconduct (PM), law enforcement (LE), and 
  counterintelligence (CI) investigations.
- At any time, the USG may inspect and seize data stored on this IS.
- Communications using, or data stored on, this IS are not private, are subject 
  to routine monitoring, interception, and search, and may be disclosed or used 
  for any USG-authorized purpose.
- This IS includes security measures (e.g., authentication and access controls) 
  to protect USG interests--not for your personal benefit or privacy.
- Notwithstanding the above, using this IS does not constitute consent to PM, LE 
  or CI investigative searching or monitoring of the content of privileged 
  communications, or work product, related to personal representation or services 
  by attorneys, psychotherapists, or clergy, and their assistants.

By continuing to use this system you indicate your awareness of and consent to 
these terms and conditions of use.
";
    
    public async Task InvokeAsync(HttpContext context)
    {
        // For API endpoints, include banner in response header
        if (context.Request.Path.StartsWithSegments("/api"))
        {
            context.Response.Headers.Append("X-DoD-Banner", "true");
        }
        
        await next(context);
    }
}

// Banner acknowledgment endpoint
[ApiController]
[Route("api/[controller]")]
public class BannerController : ControllerBase
{
    [HttpGet]
    [AllowAnonymous]
    public IActionResult GetBanner()
    {
        return Ok(new
        {
            Banner = DodBannerMiddleware.DodBanner,
            RequiresAcknowledgment = true
        });
    }
    
    [HttpPost("acknowledge")]
    public IActionResult AcknowledgeBanner()
    {
        // Log acknowledgment for audit
        HttpContext.Session.SetString("BannerAcknowledged", DateTime.UtcNow.ToString("O"));
        return Ok();
    }
}
```

---

## CIS Benchmark Level 2 Controls

### CIS Controls Applicable to .NET Applications

| Control # | Control Name | Implementation |
|-----------|--------------|----------------|
| 1 | Inventory of Enterprise Assets | Asset management integration |
| 2 | Inventory of Software Assets | NuGet package inventory |
| 3 | Data Protection | Encryption at rest/transit |
| 4 | Secure Configuration | Hardened appsettings |
| 5 | Account Management | Identity with policies |
| 6 | Access Control Management | RBAC/ABAC |
| 7 | Continuous Vulnerability Management | SAST/DAST integration |
| 8 | Audit Log Management | Structured logging |
| 9 | Email and Web Protection | Input validation, CSP |
| 10 | Malware Defenses | File upload scanning |
| 11 | Data Recovery | Backup/restore procedures |
| 12 | Network Infrastructure | Network segmentation |
| 13 | Network Monitoring | Request logging |
| 14 | Security Awareness | Developer training |
| 16 | Application Software Security | Secure SDLC |

### CIS Level 2 Implementation Examples

```csharp
// Control 3: Data Protection - Encryption configuration
public static class CisDataProtectionConfig
{
    public static IServiceCollection AddCisCompliantDataProtection(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        services.AddDataProtection()
            .SetApplicationName(configuration["App:Name"]!)
            .SetDefaultKeyLifetime(TimeSpan.FromDays(90))
            .UseCryptographicAlgorithms(new AuthenticatedEncryptorConfiguration
            {
                EncryptionAlgorithm = EncryptionAlgorithm.AES_256_GCM,
                ValidationAlgorithm = ValidationAlgorithm.HMACSHA512
            });
        
        return services;
    }
}

// Control 4: Secure Configuration
public class SecureConfigurationValidator : IStartupFilter
{
    public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next)
    {
        return app =>
        {
            var env = app.ApplicationServices.GetRequiredService<IWebHostEnvironment>();
            var config = app.ApplicationServices.GetRequiredService<IConfiguration>();
            
            // Validate security settings at startup
            if (env.IsProduction())
            {
                ValidateProductionSettings(config);
            }
            
            next(app);
        };
    }
    
    private void ValidateProductionSettings(IConfiguration config)
    {
        var errors = new List<string>();
        
        // Ensure HTTPS is enforced
        if (!bool.TryParse(config["Security:RequireHttps"], out var requireHttps) || !requireHttps)
        {
            errors.Add("HTTPS must be required in production");
        }
        
        // Ensure strong JWT secret
        var jwtSecret = config["Jwt:SecretKey"];
        if (string.IsNullOrEmpty(jwtSecret) || jwtSecret.Length < 32)
        {
            errors.Add("JWT secret key must be at least 32 characters");
        }
        
        // Ensure proper password policy
        if (!int.TryParse(config["Identity:Password:MinLength"], out var minLength) || minLength < 12)
        {
            errors.Add("Minimum password length must be at least 12 characters");
        }
        
        if (errors.Count > 0)
        {
            throw new InvalidOperationException(
                $"Security configuration errors:\n{string.Join("\n", errors)}");
        }
    }
}

// Control 7: Continuous Vulnerability Management
public class VulnerabilityCheckService(ILogger<VulnerabilityCheckService> logger)
{
    public async Task<List<VulnerabilityReport>> CheckDependenciesAsync()
    {
        var reports = new List<VulnerabilityReport>();
        
        // Run dotnet list package --vulnerable
        var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = "dotnet",
                Arguments = "list package --vulnerable --format json",
                RedirectStandardOutput = true,
                UseShellExecute = false
            }
        };
        
        process.Start();
        var output = await process.StandardOutput.ReadToEndAsync();
        await process.WaitForExitAsync();
        
        // Parse and report vulnerabilities
        if (!string.IsNullOrWhiteSpace(output))
        {
            var vulnerabilities = JsonSerializer.Deserialize<VulnerabilityOutput>(output);
            // Process vulnerabilities
            logger.LogWarning("Found {Count} vulnerable packages", 
                vulnerabilities?.Projects?.Sum(p => p.Frameworks?.Sum(f => 
                    f.TopLevelPackages?.Count ?? 0) ?? 0) ?? 0);
        }
        
        return reports;
    }
}

// Control 10: Malware Defenses - File upload scanning
public class FileUploadSecurityService
{
    private static readonly HashSet<string> AllowedExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".png", ".jpg", ".jpeg", ".gif"
    };
    
    private static readonly Dictionary<string, byte[]> FileMagicNumbers = new()
    {
        { ".pdf", new byte[] { 0x25, 0x50, 0x44, 0x46 } }, // %PDF
        { ".png", new byte[] { 0x89, 0x50, 0x4E, 0x47 } }, // .PNG
        { ".jpg", new byte[] { 0xFF, 0xD8, 0xFF } },
        { ".gif", new byte[] { 0x47, 0x49, 0x46 } }, // GIF
        { ".zip", new byte[] { 0x50, 0x4B, 0x03, 0x04 } } // PK..
    };
    
    public async Task<FileValidationResult> ValidateFileAsync(IFormFile file)
    {
        var result = new FileValidationResult();
        
        // Check extension
        var extension = Path.GetExtension(file.FileName).ToLowerInvariant();
        if (!AllowedExtensions.Contains(extension))
        {
            result.Errors.Add($"File extension '{extension}' is not allowed");
            return result;
        }
        
        // Check file size (max 10MB)
        if (file.Length > 10 * 1024 * 1024)
        {
            result.Errors.Add("File size exceeds 10MB limit");
            return result;
        }
        
        // Verify magic number matches extension
        using var stream = file.OpenReadStream();
        var header = new byte[8];
        await stream.ReadAsync(header.AsMemory(0, 8));
        
        if (FileMagicNumbers.TryGetValue(extension, out var expectedMagic))
        {
            if (!header.Take(expectedMagic.Length).SequenceEqual(expectedMagic))
            {
                result.Errors.Add("File content does not match declared type");
                return result;
            }
        }
        
        // Scan for malicious content (integrate with antivirus API)
        // await ScanWithAntivirusAsync(file);
        
        result.IsValid = result.Errors.Count == 0;
        return result;
    }
}
```

---

## FIPS 140-3 Cryptographic Requirements

### FIPS-Approved Algorithms for .NET

| Algorithm Type | Approved Algorithms | .NET API |
|---------------|---------------------|----------|
| **Symmetric Encryption** | AES (128, 192, 256) | `Aes.Create()` |
| | Triple DES (legacy) | `TripleDES.Create()` |
| **Hashing** | SHA-1 (legacy), SHA-2 family | `SHA256.Create()`, `SHA384.Create()`, `SHA512.Create()` |
| | SHA-3 family | `SHA3_256.Create()` (.NET 8+) |
| **MAC** | HMAC-SHA-1, HMAC-SHA-2 | `HMACSHA256`, `HMACSHA384`, `HMACSHA512` |
| | CMAC | Custom implementation |
| **Asymmetric** | RSA (2048+), ECDSA | `RSA.Create()`, `ECDsa.Create()` |
| | ECDH | `ECDiffieHellman.Create()` |
| **KDF** | PBKDF2, HKDF | `Rfc2898DeriveBytes`, `HKDF` |
| **RNG** | DRBG | `RandomNumberGenerator.Create()` |

### FIPS Mode Configuration

```csharp
// Enable FIPS mode in Windows
// Registry: HKLM\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy\Enabled = 1

// Check FIPS mode status
public static class FipsComplianceChecker
{
    public static bool IsFipsModeEnabled()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy");
            var enabled = key?.GetValue("Enabled");
            return enabled is int value && value == 1;
        }
        catch
        {
            return false;
        }
    }
    
    public static void ValidateFipsCompliance()
    {
        var issues = new List<string>();
        
        // Test AES
        try
        {
            using var aes = Aes.Create();
            aes.KeySize = 256;
        }
        catch (Exception ex)
        {
            issues.Add($"AES-256 not available: {ex.Message}");
        }
        
        // Test SHA-256
        try
        {
            using var sha = SHA256.Create();
            sha.ComputeHash(Array.Empty<byte>());
        }
        catch (Exception ex)
        {
            issues.Add($"SHA-256 not available: {ex.Message}");
        }
        
        // Test RSA
        try
        {
            using var rsa = RSA.Create(2048);
        }
        catch (Exception ex)
        {
            issues.Add($"RSA-2048 not available: {ex.Message}");
        }
        
        if (issues.Count > 0)
        {
            throw new CryptographicException(
                $"FIPS compliance issues:\n{string.Join("\n", issues)}");
        }
    }
}
```

### FIPS-Compliant Cryptographic Service

```csharp
public interface IFipsCryptoService
{
    byte[] EncryptAes256(byte[] plaintext, byte[] key, byte[] iv);
    byte[] DecryptAes256(byte[] ciphertext, byte[] key, byte[] iv);
    byte[] ComputeSha256(byte[] data);
    byte[] ComputeHmacSha256(byte[] data, byte[] key);
    byte[] GenerateSecureRandom(int length);
    byte[] DeriveKeyPbkdf2(string password, byte[] salt, int iterations, int keyLength);
}

public class FipsCryptoService : IFipsCryptoService
{
    // Minimum iterations per NIST SP 800-132
    private const int MinPbkdf2Iterations = 600000;
    
    public byte[] EncryptAes256(byte[] plaintext, byte[] key, byte[] iv)
    {
        if (key.Length != 32)
            throw new ArgumentException("Key must be 256 bits (32 bytes)", nameof(key));
        if (iv.Length != 16)
            throw new ArgumentException("IV must be 128 bits (16 bytes)", nameof(iv));
        
        using var aes = Aes.Create();
        aes.KeySize = 256;
        aes.BlockSize = 128;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        aes.Key = key;
        aes.IV = iv;
        
        using var encryptor = aes.CreateEncryptor();
        return encryptor.TransformFinalBlock(plaintext, 0, plaintext.Length);
    }
    
    public byte[] DecryptAes256(byte[] ciphertext, byte[] key, byte[] iv)
    {
        if (key.Length != 32)
            throw new ArgumentException("Key must be 256 bits (32 bytes)", nameof(key));
        if (iv.Length != 16)
            throw new ArgumentException("IV must be 128 bits (16 bytes)", nameof(iv));
        
        using var aes = Aes.Create();
        aes.KeySize = 256;
        aes.BlockSize = 128;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        aes.Key = key;
        aes.IV = iv;
        
        using var decryptor = aes.CreateDecryptor();
        return decryptor.TransformFinalBlock(ciphertext, 0, ciphertext.Length);
    }
    
    public byte[] ComputeSha256(byte[] data)
    {
        return SHA256.HashData(data);
    }
    
    public byte[] ComputeHmacSha256(byte[] data, byte[] key)
    {
        return HMACSHA256.HashData(key, data);
    }
    
    public byte[] GenerateSecureRandom(int length)
    {
        return RandomNumberGenerator.GetBytes(length);
    }
    
    public byte[] DeriveKeyPbkdf2(string password, byte[] salt, int iterations, int keyLength)
    {
        if (iterations < MinPbkdf2Iterations)
            throw new ArgumentException(
                $"Iterations must be at least {MinPbkdf2Iterations}", nameof(iterations));
        
        return Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(password),
            salt,
            iterations,
            HashAlgorithmName.SHA256,
            keyLength);
    }
}

// FIPS-compliant TLS configuration
public static class FipsTlsConfiguration
{
    public static void ConfigureFipsCompliantTls()
    {
        // Only allow FIPS-approved TLS versions and cipher suites
        ServicePointManager.SecurityProtocol = 
            SecurityProtocolType.Tls12 | SecurityProtocolType.Tls13;
        
        // For HttpClient
        var handler = new SocketsHttpHandler
        {
            SslOptions = new SslClientAuthenticationOptions
            {
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                CipherSuitesPolicy = new CipherSuitesPolicy(new[]
                {
                    // TLS 1.3 FIPS-approved cipher suites
                    TlsCipherSuite.TLS_AES_256_GCM_SHA384,
                    TlsCipherSuite.TLS_AES_128_GCM_SHA256,
                    // TLS 1.2 FIPS-approved cipher suites
                    TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                    TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                    TlsCipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
                    TlsCipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
                })
            }
        };
    }
}
```

---

## Compliance Checklists

### Pre-Deployment Security Checklist

#### Authentication & Authorization
- [ ] Strong password policy enforced (min 12-15 chars, complexity)
- [ ] Account lockout configured (3-5 attempts, 15-30 min lockout)
- [ ] Multi-factor authentication enabled for privileged accounts
- [ ] JWT tokens have appropriate expiration (15-60 minutes)
- [ ] Refresh token rotation implemented
- [ ] Role-based access control properly configured
- [ ] Resource-based authorization for sensitive data

#### Input Validation
- [ ] All user inputs validated on server-side
- [ ] Data annotation attributes applied to DTOs
- [ ] SQL injection prevented via parameterized queries
- [ ] XSS prevented via output encoding
- [ ] CSRF tokens implemented for state-changing operations
- [ ] File upload validation (type, size, content scanning)

#### Cryptography
- [ ] HTTPS enforced with HSTS
- [ ] TLS 1.2+ only
- [ ] AES-256 for symmetric encryption
- [ ] RSA-2048+ for asymmetric operations
- [ ] Passwords hashed with Argon2id or PBKDF2 (600k+ iterations)
- [ ] Secrets stored in secure vault (not in code/config)

#### Security Headers
- [ ] Content-Security-Policy configured
- [ ] X-Frame-Options: DENY
- [ ] X-Content-Type-Options: nosniff
- [ ] X-XSS-Protection: 1; mode=block
- [ ] Referrer-Policy configured
- [ ] Permissions-Policy configured

#### Logging & Monitoring
- [ ] Security events logged
- [ ] Audit trail for authentication attempts
- [ ] Audit trail for data access/modification
- [ ] Log files protected from unauthorized access
- [ ] SIEM integration configured
- [ ] Alerting for security events

#### Session Management
- [ ] Session timeout configured (15 min idle for users, 10 min for admins)
- [ ] Session cookie flags: HttpOnly, Secure, SameSite=Strict
- [ ] Session fixation protection enabled
- [ ] Session invalidation on logout

### DISA STIG Compliance Checklist

| Category | Finding ID | Requirement | Status |
|----------|-----------|-------------|--------|
| **Auth** | V-222522 | Unique user identification | [ ] |
| | V-222523 | MFA for network access | [ ] |
| | V-222536 | 15-char min password | [ ] |
| | V-222432 | 3 logon attempt limit | [ ] |
| **Session** | V-222389 | 15-min user timeout | [ ] |
| | V-222390 | 10-min admin timeout | [ ] |
| | V-222575 | HTTPOnly cookie flag | [ ] |
| | V-222576 | Secure cookie flag | [ ] |
| **Crypto** | V-222570 | FIPS crypto for signing | [ ] |
| | V-222571 | FIPS crypto for hashing | [ ] |
| | V-222588 | Data at rest encryption | [ ] |
| **Input** | V-222602 | XSS protection | [ ] |
| | V-222607 | SQL injection protection | [ ] |
| | V-222604 | Command injection protection | [ ] |
| **Audit** | V-222441 | Session audit logging | [ ] |
| | V-222462 | Logon attempt logging | [ ] |
| | V-222500 | Audit log protection | [ ] |
| **Config** | V-222662 | Default passwords changed | [ ] |
| | V-222614 | Software patches current | [ ] |
| | V-222518 | Non-essential features disabled | [ ] |

### OWASP Top Ten Compliance Matrix

| Vulnerability | Mitigation Implemented | Test Verified | Notes |
|--------------|------------------------|---------------|-------|
| A01: Broken Access Control | [ ] | [ ] | |
| A02: Cryptographic Failures | [ ] | [ ] | |
| A03: Injection | [ ] | [ ] | |
| A04: Insecure Design | [ ] | [ ] | |
| A05: Security Misconfiguration | [ ] | [ ] | |
| A06: Vulnerable Components | [ ] | [ ] | |
| A07: Auth Failures | [ ] | [ ] | |
| A08: Data Integrity Failures | [ ] | [ ] | |
| A09: Logging Failures | [ ] | [ ] | |
| A10: SSRF | [ ] | [ ] | |

---

## References

### Official Documentation

1. [Microsoft .NET Security Documentation](https://learn.microsoft.com/en-us/dotnet/standard/security/) - Official .NET security guidelines
2. [ASP.NET Core Security](https://learn.microsoft.com/en-us/aspnet/core/security/) - ASP.NET Core security documentation
3. [OWASP Top Ten 2021](https://owasp.org/www-project-top-ten/) - OWASP Top 10 vulnerability list
4. [NIST SP 800-53 Rev. 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final) - Security and Privacy Controls
5. [DISA STIGs](https://www.cyber.mil/stigs/downloads/) - Security Technical Implementation Guides
6. [CIS Controls](https://www.cisecurity.org/controls) - Center for Internet Security Controls
7. [FIPS 140-3](https://csrc.nist.gov/pubs/fips/140-3/final) - Cryptographic Module Requirements

### Additional Resources

8. [Microsoft Secure Coding Guidelines](https://learn.microsoft.com/en-us/dotnet/standard/security/secure-coding-guidelines) - Secure coding best practices
9. [OWASP .NET Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/DotNet_Security_Cheat_Sheet.html) - .NET-specific security guidance
10. [NIST Cryptographic Algorithm Validation Program](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program) - Validated cryptographic algorithms
11. [Application Security and Development STIG](https://www.stigviewer.com/stigs/application_security_and_development) - DISA application security requirements
12. [Entity Framework Security Considerations](https://learn.microsoft.com/en-us/dotnet/framework/data/adonet/ef/security-considerations) - EF security guidance

### Tools and Analyzers

13. [Security Code Scan](https://security-code-scan.github.io/) - Static analysis for .NET security
14. [.NET Analyzers](https://learn.microsoft.com/en-us/dotnet/fundamentals/code-analysis/overview) - Built-in code analyzers
15. [OWASP ZAP](https://www.zaproxy.org/) - Dynamic application security testing
16. [Snyk](https://snyk.io/) - Vulnerability scanning for dependencies

---

## Document Control

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | March 2026 | Matrix Agent | Initial release |

---

**Disclaimer:** This guide provides security best practices and compliance guidance. Implementation details may vary based on specific requirements, threat models, and organizational policies. Always consult with security professionals and conduct thorough testing before deploying to production environments.
