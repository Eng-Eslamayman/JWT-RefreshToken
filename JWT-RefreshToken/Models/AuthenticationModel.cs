using System.Text.Json.Serialization;

namespace JWT_RefreshToken.Models
{
    public class AuthenticationModel
    {
        public DateTime ExpiresOn { get; set; }
        public string? UserName { get; set; }
        public string? Message { get; set; }
        public string? Email { get; set; }
        public string? Token { get; set; }
        public List<string>? Roles { get; set; }
        public bool IsAuthenticated { get; set; }
        [JsonIgnore]
        public string? RefreshToken{ get; set; }
        public DateTime RefreshTokenExpiration { get; set; }
    }
}
