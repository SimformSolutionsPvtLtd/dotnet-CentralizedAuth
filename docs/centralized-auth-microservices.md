# Building a Centralized Authentication System for .NET Microservices with Azure Entra ID

## A Comprehensive Guide to Implementing Secure Authentication Across Your Microservices Architecture

### Topic Overview
In today's distributed application landscape, managing authentication across multiple microservices can be challenging. This blog post explores how to implement a centralized authentication system using Azure Entra ID (formerly Azure AD) for .NET microservices. We'll cover the implementation details, best practices, and provide a working example that you can use as a reference for your own projects.

### Features
- Centralized authentication and authorization using Azure Entra ID
- JWT token-based authentication
- Role-based access control (RBAC)
- Single Sign-On (SSO) across microservices
- Secure token validation and refresh mechanisms
- Integration with .NET Identity framework
- Support for both interactive and non-interactive authentication flows
- Built-in security features like token lifetime management and revocation

### Advantages
1. **Enhanced Security**
   - Centralized identity management
   - Industry-standard security protocols
   - Regular security updates and compliance features
   - Built-in protection against common security threats

2. **Simplified Management**
   - Single source of truth for user identities
   - Unified user management and administration
   - Reduced operational overhead
   - Easier compliance management

3. **Improved User Experience**
   - Single Sign-On across all services
   - Consistent authentication experience
   - Reduced password fatigue
   - Support for modern authentication methods

4. **Scalability and Performance**
   - Distributed token validation
   - Efficient token caching
   - Support for high-traffic scenarios
   - Easy integration with new services

### Use Cases
1. **Enterprise Applications**
   - Internal employee portals
   - Customer-facing applications
   - Partner access management
   - Multi-tenant SaaS applications

2. **E-commerce Platforms**
   - Customer authentication
   - Order management systems
   - Inventory management
   - Payment processing services

3. **Healthcare Systems**
   - Patient portals
   - Medical record management
   - Healthcare provider access
   - Compliance with healthcare regulations

4. **Financial Services**
   - Banking applications
   - Investment platforms
   - Insurance services
   - Financial reporting systems

### Prerequisites
- Azure subscription
- Visual Studio 2022 or later
- .NET 8.0 SDK
- Azure CLI (optional)
- Basic understanding of microservices architecture
- Familiarity with Azure Entra ID concepts

### Required NuGet Packages
```xml
<PackageReference Include="Microsoft.AspNetCore.Authentication.JwtBearer" Version="8.0.0" />
<PackageReference Include="Microsoft.AspNetCore.Authentication.OpenIdConnect" Version="8.0.0" />
<PackageReference Include="Microsoft.Identity.Web" Version="2.15.2" />
<PackageReference Include="Microsoft.Identity.Web.UI" Version="2.15.2" />
<PackageReference Include="Microsoft.Identity.Client" Version="4.58.1" />
```

### Configuration
1. **Azure Entra ID Setup**
   - Register your application in Azure Portal
   - Configure authentication settings
   - Set up app roles and permissions
   - Configure redirect URIs

2. **Application Configuration**
   ```json
   {
     "AzureAd": {
       "Instance": "https://login.microsoftonline.com/",
       "TenantId": "your-tenant-id",
       "ClientId": "your-client-id",
       "ClientSecret": "your-client-secret",
       "CallbackPath": "/signin-oidc"
     }
   }
   ```

### Code Examples

1. **Program.cs Configuration**
```csharp
var builder = WebApplication.CreateBuilder(args);

// Add authentication services
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddMicrosoftIdentityWebApi(builder.Configuration.GetSection("AzureAd"));

// Add authorization
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("RequireAdminRole", policy =>
        policy.RequireRole("Admin"));
});

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();
```

2. **Authentication Controller**
```csharp
[ApiController]
[Route("api/[controller]")]
[Authorize]
public class AuthController : ControllerBase
{
    private readonly ITokenAcquisition _tokenAcquisition;
    private readonly IConfiguration _configuration;

    public AuthController(ITokenAcquisition tokenAcquisition, IConfiguration configuration)
    {
        _tokenAcquisition = tokenAcquisition;
        _configuration = configuration;
    }

    [HttpGet("profile")]
    public async Task<IActionResult> GetUserProfile()
    {
        var user = User;
        var claims = user.Claims.Select(c => new { c.Type, c.Value });
        return Ok(claims);
    }

    [HttpGet("token")]
    [Authorize(Roles = "Admin")]
    public async Task<IActionResult> GetTokenForDownstreamApi()
    {
        try
        {
            string[] scopes = new string[] { "api://downstream-api-scope" };
            string accessToken = await _tokenAcquisition.GetAccessTokenForUserAsync(scopes);
            return Ok(new { accessToken });
        }
        catch (Exception ex)
        {
            return StatusCode(500, ex.Message);
        }
    }
}
```

3. **Protected API Endpoint**
```csharp
[ApiController]
[Route("api/[controller]")]
[Authorize]
public class SecureController : ControllerBase
{
    [HttpGet]
    [Authorize(Roles = "Admin")]
    public IActionResult GetSecureData()
    {
        return Ok(new { message = "This is secure data", user = User.Identity.Name });
    }
}
```

4. **Token Validation Middleware**
```csharp
public class TokenValidationMiddleware
{
    private readonly RequestDelegate _next;
    private readonly IConfiguration _configuration;

    public TokenValidationMiddleware(RequestDelegate next, IConfiguration configuration)
    {
        _next = next;
        _configuration = configuration;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var token = context.Request.Headers["Authorization"].ToString().Replace("Bearer ", "");

        if (!string.IsNullOrEmpty(token))
        {
            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                var key = Encoding.ASCII.GetBytes(_configuration["AzureAd:ClientSecret"]);
                
                tokenHandler.ValidateToken(token, new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidIssuer = _configuration["AzureAd:Instance"] + _configuration["AzureAd:TenantId"],
                    ValidAudience = _configuration["AzureAd:ClientId"],
                    ClockSkew = TimeSpan.Zero
                }, out SecurityToken validatedToken);
            }
            catch
            {
                context.Response.StatusCode = 401;
                await context.Response.WriteAsync("Invalid token");
                return;
            }
        }

        await _next(context);
    }
}
```

### Conclusion
Implementing a centralized authentication system using Azure Entra ID for .NET microservices provides a robust, secure, and scalable solution for managing user identities and access control. By following the patterns and examples provided in this blog post, you can create a secure authentication system that:

- Centralizes identity management
- Provides a consistent user experience
- Scales with your application
- Maintains high security standards
- Simplifies compliance requirements

Remember to:
- Regularly update your dependencies
- Monitor authentication logs
- Implement proper error handling
- Follow security best practices
- Test thoroughly in a staging environment

The example code provided serves as a starting point that you can customize based on your specific requirements. Always ensure you follow security best practices and keep your application updated with the latest security patches.

### Next Steps
1. Set up your Azure Entra ID tenant
2. Register your application
3. Implement the authentication system
4. Test the integration
5. Deploy to production

For more information, refer to the official Microsoft documentation:
- [Azure Entra ID Documentation](https://learn.microsoft.com/en-us/azure/active-directory/)
- [Microsoft Identity Platform](https://learn.microsoft.com/en-us/azure/active-directory/develop/)
- [.NET Authentication Documentation](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/) 