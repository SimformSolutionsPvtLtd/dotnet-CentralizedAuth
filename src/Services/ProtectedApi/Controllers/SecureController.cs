using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace ProtectedApi.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize]
public class SecureController : ControllerBase
{
    private readonly ILogger<SecureController> _logger;

    public SecureController(ILogger<SecureController> logger)
    {
        _logger = logger;
    }

    [HttpGet]
    [Authorize(Roles = "Admin")]
    public IActionResult GetAdminData()
    {
        try
        {
            var user = User;
            return Ok(new
            {
                Message = "This is admin-only data",
                User = user.Identity?.Name,
                Roles = user.Claims
                    .Where(c => c.Type == ClaimTypes.Role)
                    .Select(c => c.Value)
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting admin data");
            return StatusCode(500, "Error retrieving admin data");
        }
    }

    [HttpGet("user")]
    [Authorize(Roles = "User")]
    public IActionResult GetUserData()
    {
        try
        {
            var user = User;
            return Ok(new
            {
                Message = "This is user data",
                User = user.Identity?.Name,
                Roles = user.Claims
                    .Where(c => c.Type == ClaimTypes.Role)
                    .Select(c => c.Value)
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting user data");
            return StatusCode(500, "Error retrieving user data");
        }
    }

    [HttpGet("public")]
    [AllowAnonymous]
    public IActionResult GetPublicData()
    {
        return Ok(new { Message = "This is public data" });
    }

    [HttpGet("claims")]
    public IActionResult GetUserClaims()
    {
        try
        {
            var claims = User.Claims.Select(c => new { c.Type, c.Value });
            return Ok(claims);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting user claims");
            return StatusCode(500, "Error retrieving user claims");
        }
    }
} 