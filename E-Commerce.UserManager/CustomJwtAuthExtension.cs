using E_Commerce.UserManager.Data;
using E_Commerce.UserManager.Models;
using E_Commerce.UserManager.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using System.Text;

namespace E_Commerce.UserManager
{
    public static class IdentityManagerExtension
    {
        public const string CONFIG = "Server=DESKTOP-SPSJDRK\\SQLEXPRESS;Database=LOJA;Trusted_Connection=True;TrustServerCertificate=True;";

        public static void AddJwtAutentication(this IServiceCollection services)
        {
            services.AddDbContext<AppIdentityDbContext>(options => options.UseSqlServer(CONFIG));
            services.AddIdentity<ApplicationUser, IdentityRole>()
                .AddEntityFrameworkStores<AppIdentityDbContext>()
                .AddDefaultTokenProviders();
            services.AddScoped<AuthService>();
            services.AddAuthentication(o =>
            {
                o.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                o.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            }).AddJwtBearer(o =>
            {
                o.RequireHttpsMetadata = false;
                o.SaveToken = true;
                o.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidIssuer = "localhost",  
                    ValidAudience = "localhost", 
                    IssuerSigningKey = new SymmetricSecurityKey(Convert.FromBase64String((AuthService.JWT_SECURIRY_KEY))) 
                };
            });

        }
    }
}
