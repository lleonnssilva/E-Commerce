namespace E_Commerce.UserManager
{
    //public class JwtTokenHandler
    //{
        //public const string JWT_SECURIRY_KEY = "@@AppAuth2022_@@AppAuth2023_@@AppAuth2024_@@AppAuth2025";
        //private const int JWT_TOKEN_VALIDITY_MINS = 30;
        //private readonly List<UserAccount> _userAccountList;
        //public JwtTokenHandler()
        //{
        //    _userAccountList = new List<UserAccount>
        //    {
        //        new UserAccount {UserName="admin",Password="admin123",Role="Administrador"},
        //        new UserAccount {UserName="user01",Password="user01",Role="user"},
        //    };

        //}

        //public AuthenticationResponse? GenerateJwtToken(AuthenticationRequest authenticationRequest)
        //{
        //    if (string.IsNullOrWhiteSpace(authenticationRequest.UserName) || string.IsNullOrWhiteSpace(authenticationRequest.Password))
        //        return null;

        //    var userAccount = _userAccountList.Where(x => x.UserName == authenticationRequest.UserName && x.Password == authenticationRequest.Password).FirstOrDefault();
        //    if (userAccount == null)
        //        return null;

        //    var tokenExpiryTimeStamp = DateTime.UtcNow.AddMinutes(JWT_TOKEN_VALIDITY_MINS);
        //    var tokeKey = Encoding.ASCII.GetBytes(JWT_SECURIRY_KEY);
        //    var claimsIdentity = new ClaimsIdentity(new List<Claim>
        //    {
        //        new Claim(JwtRegisteredClaimNames.Name,authenticationRequest.UserName),
        //        new Claim(ClaimTypes.Role,userAccount.Role)
        //    });

        //    var signingCredentials = new SigningCredentials(
        //        new SymmetricSecurityKey(tokeKey),
        //        SecurityAlgorithms.HmacSha256Signature);


        //    var securityTokenDescriptor = new SecurityTokenDescriptor
        //    {
        //        Subject = claimsIdentity,
        //        Expires = tokenExpiryTimeStamp,
        //        SigningCredentials = signingCredentials
        //    };

        //    var jwtSecurityTokenHandler = new JwtSecurityTokenHandler();
        //    var securityToken = jwtSecurityTokenHandler.CreateToken(securityTokenDescriptor);
        //    var token = jwtSecurityTokenHandler.WriteToken(securityToken);

        //    return new AuthenticationResponse
        //    {
        //        UserName = authenticationRequest.UserName,
        //        ExpireIn = (int)tokenExpiryTimeStamp.Subtract(DateTime.Now).TotalSeconds,
        //        JwtToken = token,
        //    };

        //}
    //}
}
