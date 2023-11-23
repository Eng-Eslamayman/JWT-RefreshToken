namespace JWT_RefreshToken.Helpers
{
    public class JWT
    {
        public string Issuer { get; set; }
        public string Audiance { get; set; }
        public double DurationInDays { get; set; }
        public string Key { get; set; }
    }
}
