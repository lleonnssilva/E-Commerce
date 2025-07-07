namespace E_Commerce.Authentication.Models
{
    public class AuthenticationResponse
    {
        public string UserName { get; set; }
        public string JwtToken { get; set; }
        public int ExpireIn { get; set; }
    }
}
