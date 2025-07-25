﻿namespace E_Commerce.UserManager.Models
{
    public class AuthenticationResponse
    {
        public string UserName { get; set; }
        public string JwtToken { get; set; }
        public int ExpireIn { get; set; }
    }

    public class UserCreateResponse
    {
        public string UserName { get; set; }
        public string JwtToken { get; set; }
        public int ExpireIn { get; set; }
    }
}
