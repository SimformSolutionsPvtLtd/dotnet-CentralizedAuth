using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Identity.Web;
using System.Security.Claims;

namespace AuthService.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize]
public class AuthController : ControllerBase
{
    private readonly ITokenAcquisition _tokenAcquisition;
    private readonly IConfiguration _configuration;
    private readonly ILogger<AuthController> _logger;

    public AuthController(
        ITokenAcquisition tokenAcquisition,
        IConfiguration configuration,
        ILogger<AuthController> logger)
    {
        _tokenAcquisition = tokenAcquisition;
        _configuration = configuration;
        _logger = logger;
    }

    [HttpGet("profile")]
    public IActionResult GetUserProfile()
    {
        try
        {
            var user = User;
            var claims = user.Claims.Select(c => new { c.Type, c.Value });
            return Ok(new
            {
                Name = user.Identity?.Name,
                Claims = claims,
                Roles = user.Claims
                    .Where(c => c.Type == ClaimTypes.Role)
                    .Select(c => c.Value)
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting user profile");
            return StatusCode(500, "Error retrieving user profile");
        }
    }

    [HttpGet("token")]
    [Authorize(Roles = "Admin")]
    public async Task<IActionResult> GetTokenForDownstreamApi()
    {
        try
        {
            string[] scopes = new string[] { "api://protected-api-scope" };
            string accessToken = await _tokenAcquisition.GetAccessTokenForUserAsync(scopes);
            return Ok(new { accessToken });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error acquiring token for downstream API");
            return StatusCode(500, "Error acquiring token for downstream API");
        }
    }

    [HttpGet("validate")]
    public IActionResult ValidateToken()
    {
        try
        {
            var user = User;
            if (user.Identity?.IsAuthenticated != true)
            {
                return Unauthorized();
            }

            return Ok(new
            {
                IsValid = true,
                UserName = user.Identity.Name,
                Roles = user.Claims
                    .Where(c => c.Type == ClaimTypes.Role)
                    .Select(c => c.Value)
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error validating token");
            return StatusCode(500, "Error validating token");
        }
    }

    [HttpGet("roles")]
    [Authorize(Roles = "Admin")]
    public IActionResult GetUserRoles()
    {
        try
        {
            var roles = User.Claims
                .Where(c => c.Type == ClaimTypes.Role)
                .Select(c => c.Value)
                .ToList();

            return Ok(new { Roles = roles });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting user roles");
            return StatusCode(500, "Error retrieving user roles");
        }
    }
} 