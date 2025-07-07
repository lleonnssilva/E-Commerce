using E_Commerce.Authentication;
using E_Commerce.Authentication.Models;
using Microsoft.AspNetCore.Mvc;

namespace E_Commerce.AuthenticationApi.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AccountsController : ControllerBase
    {
        private readonly JwtTokenHandler _jwtTokenHandler;



        public AccountsController(JwtTokenHandler jwtTokenHandler)
        {
            _jwtTokenHandler = jwtTokenHandler;
        }

        [HttpGet]
        public ActionResult<List<string>> GetAccounts()
        {
            List<string> Accounts = new List<string>();
            Accounts.Add("Account 1");
            Accounts.Add("Account 2");
            Accounts.Add("Account 3");
            Accounts.Add("Account 4");
            Accounts.Add("Account 5");
            Accounts.Add("Account 6");
            Accounts.Add("Account 7");
            Accounts.Add("Account 8");
            Accounts.Add("Account 9");
            Accounts.Add("Account 10");
            return Accounts.ToList();
        }

        [HttpPost]
        public ActionResult<AuthenticationResponse> Authenticate([FromBody] AuthenticationRequest authenticationRequest)
        {
            var authenticationResponse = _jwtTokenHandler.GenerateJwtToken(authenticationRequest);
            if (authenticationResponse == null) return Unauthorized();
            return authenticationResponse;
        }
    }
}
