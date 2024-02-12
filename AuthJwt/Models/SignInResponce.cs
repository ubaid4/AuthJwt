namespace AuthJwt.Models
{
    public class SignInResponce
    {
        public string? UserName { get; set; }
        public string? Phone { get; set; }
        public string? Token { get; set;}
        public DateTime? ExpirationTime { get; set;}
    }
}
