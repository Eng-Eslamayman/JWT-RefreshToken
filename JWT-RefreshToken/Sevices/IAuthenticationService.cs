using JWT_RefreshToken.Models;

namespace JWT_RefreshToken.Sevices
{
    public interface IAuthenticationService
    {
        Task<AuthenticationModel> RegistrationAsync(RegisterModel model);
        Task<AuthenticationModel> LoginAsync(TokenRequestModel model);
        Task<string> AddRoleAsync(RoleModel model);
        Task<AuthenticationModel> RefreshTokenAsync(string token);
        Task<bool> RevokeTokenAsync(string token); 
    }
}
