# Centralized Authentication System for .NET Microservices with Azure Entra ID

This solution demonstrates how to implement a centralized authentication system using Azure Entra ID (formerly Azure AD) for .NET microservices. It includes two services:

1. **AuthService**: Handles authentication and token management
2. **ProtectedApi**: A sample API that requires authentication

## Prerequisites

- Azure subscription
- Visual Studio 2022 or later
- .NET 8.0 SDK
- Azure CLI (optional)

## Setup Instructions

### 1. Azure Entra ID Configuration

1. Sign in to the [Azure Portal](https://portal.azure.com)
2. Navigate to Azure Entra ID
3. Register two applications:
   - AuthService (Web API)
   - ProtectedApi (Web API)
4. Configure the following for each application:
   - Authentication
   - API permissions
   - App roles (Admin and User)
   - Expose an API (for ProtectedApi)

### 2. Application Configuration

1. Update the `appsettings.json` files in both projects with your Azure Entra ID settings:
   - TenantId
   - ClientId
   - ClientSecret (for AuthService only)
   - Audience
   - Scopes

### 3. Running the Solution

1. Open the solution in Visual Studio
2. Set both projects as startup projects:
   - Right-click on the solution
   - Select "Set Startup Projects"
   - Choose "Multiple startup projects"
   - Set both AuthService and ProtectedApi to "Start"

3. Press F5 to run the solution

## API Endpoints

### AuthService

- `GET /api/auth/profile` - Get user profile and claims
- `GET /api/auth/token` - Get token for downstream API (Admin only)
- `GET /api/auth/validate` - Validate current token
- `GET /api/auth/roles` - Get user roles (Admin only)

### ProtectedApi

- `GET /api/secure` - Get admin-only data
- `GET /api/secure/user` - Get user data
- `GET /api/secure/public` - Get public data (no auth required)
- `GET /api/secure/claims` - Get user claims

## Testing the APIs

1. Use Swagger UI:
   - AuthService: https://localhost:7001/swagger
   - ProtectedApi: https://localhost:7002/swagger

2. Use tools like Postman:
   - Get a token from AuthService
   - Use the token in the Authorization header for ProtectedApi requests

## Security Considerations

1. Always use HTTPS in production
2. Store secrets in Azure Key Vault
3. Implement proper error handling
4. Use appropriate token lifetimes
5. Implement token revocation
6. Monitor authentication logs
7. Regular security updates

## Additional Resources

- [Azure Entra ID Documentation](https://learn.microsoft.com/en-us/azure/active-directory/)
- [Microsoft Identity Platform](https://learn.microsoft.com/en-us/azure/active-directory/develop/)
- [.NET Authentication Documentation](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/)

## Contributing

Feel free to submit issues and enhancement requests!

## License

This project is licensed under the MIT License - see the LICENSE file for details. 