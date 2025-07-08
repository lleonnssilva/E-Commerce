using E_Commerce.UserManager.Models;
using E_Commerce.UserManager.Services;
using Microsoft.AspNetCore.Mvc;

namespace E_Commerce.AuthenticationApi.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AccountsController : ControllerBase
    {
        private readonly AuthService _authService;
        public AccountsController(AuthService authService)
        {
            _authService = authService;
        }

        [HttpPost("authenticate")]
        public async Task<ActionResult<AuthenticationResponse>> Authenticate([FromBody] AuthenticationRequest authenticationRequest)
        {
            var authenticationResponse = await _authService.Autenticate(authenticationRequest);
            if (authenticationResponse == null) return Unauthorized();
            return authenticationResponse;
        }

        [HttpPost("register")]
        public async Task<ActionResult<UserCreateResponse>> Register(UserCreateRequest request)
        {
            var userCreateResponse = await _authService.RegisterAsync(request);
            if (userCreateResponse == null) return BadRequest();
            return userCreateResponse;
        }
    }
}
