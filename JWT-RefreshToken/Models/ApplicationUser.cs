using Microsoft.AspNetCore.Identity;

namespace JWT_RefreshToken.Models
{
    public class ApplicationUser:IdentityUser
    {
        public string FirstName { get; set; } = null!;
        public string LastName { get; set; } = null!;
        public List<RefreshToken>? RefreshTokens { get; set; }
    }
}
 