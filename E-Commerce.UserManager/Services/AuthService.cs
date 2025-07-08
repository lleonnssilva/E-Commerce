using E_Commerce.UserManager.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace E_Commerce.UserManager.Services
{
    public class AuthService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        public const string JWT_SECURIRY_KEY = "ZjI5ODU4Y2FhYjY4YTc2Y2MwZjdiMjk1MjNkODJlNzExZjFmZDFhYmQ4ZjMwN2JjZ2FiNmFiMw==";
        private const int JWT_TOKEN_VALIDITY_MINS = 30;


        public AuthService(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, RoleManager<IdentityRole> roleManager)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _roleManager = roleManager;
        }

        public async Task<AuthenticationResponse?> Autenticate(AuthenticationRequest authenticationRequest)
        {
            if (string.IsNullOrWhiteSpace(authenticationRequest.UserName) || string.IsNullOrWhiteSpace(authenticationRequest.Password))
                return null;


            SignInResult signInResult = await _signInManager.PasswordSignInAsync(authenticationRequest.UserName, authenticationRequest.Password, true, false);
            if (signInResult.Succeeded)
            {
                var user = await _userManager.FindByNameAsync(authenticationRequest.UserName);
                if (user == null)
                    return null;

                var rolesClaims = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.Sub, authenticationRequest.UserName), 
            new Claim(JwtRegisteredClaimNames.Name, authenticationRequest.UserName),
            new Claim(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64), 
            new Claim(JwtRegisteredClaimNames.Exp, DateTimeOffset.UtcNow.AddMinutes(JWT_TOKEN_VALIDITY_MINS).ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64), 
        };

                var roles = await _userManager.GetRolesAsync(user);
                foreach (var role in roles)
                {
                    rolesClaims.Add(new Claim(ClaimTypes.Role, role));
                }


                var claimsIdentity = new ClaimsIdentity(rolesClaims);
                var tokenExpiryTimeStamp = DateTime.UtcNow.AddMinutes(JWT_TOKEN_VALIDITY_MINS);
                var tokenKey = Convert.FromBase64String(JWT_SECURIRY_KEY);

                var signingCredentials = new SigningCredentials(
                    new SymmetricSecurityKey(tokenKey),
                    SecurityAlgorithms.HmacSha256);


                var securityTokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = claimsIdentity,
                    Expires = tokenExpiryTimeStamp,
                    Issuer = "http://localhost", 
                    Audience = "http://localhost", 
                    SigningCredentials = signingCredentials
                };

                var jwtSecurityTokenHandler = new JwtSecurityTokenHandler();
                var securityToken = jwtSecurityTokenHandler.CreateToken(securityTokenDescriptor);
                var token = jwtSecurityTokenHandler.WriteToken(securityToken);

                return new AuthenticationResponse
                {
                    UserName = authenticationRequest.UserName,
                    ExpireIn = (int)tokenExpiryTimeStamp.Subtract(DateTime.Now).TotalSeconds,
                    JwtToken = token,
                };
            }

            return null;
        }

        public async Task<UserCreateResponse?> RegisterAsync(UserCreateRequest request)
        {
            ApplicationUser user = new ApplicationUser
            {
                UserName = request.UserName
            };

            IdentityResult result = await _userManager.CreateAsync(user, request.Password);

            if (!result.Succeeded)
                return null;


            var role = "User";
            if (!await _roleManager.RoleExistsAsync(role))
            {
                await _roleManager.CreateAsync(new IdentityRole(role));
            }

            await _userManager.AddToRoleAsync(user, role);

            var tokenExpiryTimeStamp = DateTime.UtcNow.AddMinutes(JWT_TOKEN_VALIDITY_MINS);
            var tokenKey = Encoding.ASCII.GetBytes(JWT_SECURIRY_KEY);

            var claimsIdentity = new ClaimsIdentity(new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Name, request.UserName),
                new Claim(ClaimTypes.Role,role )
            });


            var signingCredentials = new SigningCredentials(
                new SymmetricSecurityKey(tokenKey),
                SecurityAlgorithms.HmacSha256Signature);

            var securityTokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = claimsIdentity,
                Expires = tokenExpiryTimeStamp,
                SigningCredentials = signingCredentials
            };

            var jwtSecurityTokenHandler = new JwtSecurityTokenHandler();
            var securityToken = jwtSecurityTokenHandler.CreateToken(securityTokenDescriptor);
            var token = jwtSecurityTokenHandler.WriteToken(securityToken);

            return new UserCreateResponse
            {
                UserName = request.UserName,
                ExpireIn = (int)tokenExpiryTimeStamp.Subtract(DateTime.Now).TotalSeconds,
                JwtToken = token,
            };

        }

        public string GenerateJwtToken(string username)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(JWT_SECURIRY_KEY));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var claims = new[]
            {
            new Claim("sub", username), // sub é o assunto (usuário)
            new Claim("iat", DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString()), // hora de criação
            new Claim("exp", DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds().ToString()) // hora de expiração
        };

            var token = new JwtSecurityToken(
                issuer: "localhost",
                audience: "localhost",
                claims: claims,
                expires: DateTime.UtcNow.AddHours(1),
                signingCredentials: credentials
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
