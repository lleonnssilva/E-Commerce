using AutoMapper;
using E_Commerce.Authentication.Models;
using E_Commerce.UserManager.Models;

namespace E_Commerce.UserManager.Mapper
{
    public class InfrastructureProfile : Profile
    {
        public InfrastructureProfile()
        {
            CreateMap<ApplicationUser, ApplicationUserDto>()
                .ReverseMap();
        }
    }
}
