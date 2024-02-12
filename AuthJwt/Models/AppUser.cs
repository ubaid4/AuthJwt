using Microsoft.AspNetCore.Identity;

namespace AuthJwt.Models
{
    public class AppUser : IdentityUser<Guid>
    {
        public string? PersonalName { get; set; }
        public string? Address { get; set; }
    }
}
