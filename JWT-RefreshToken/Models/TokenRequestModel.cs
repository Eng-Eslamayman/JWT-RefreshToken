namespace JWT_RefreshToken.Models
{
    public class TokenRequestModel
    {
        public string Email { get; set; } = null!;
        public string password { get; set; } = null!;
    }
}