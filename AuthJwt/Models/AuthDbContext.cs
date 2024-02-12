using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace AuthJwt.Models
{
    public class AuthDbContext:IdentityDbContext<AppUser,AppRole,Guid>
    {
        public AuthDbContext(DbContextOptions options) : base(options) 
        { 
        }
        public virtual DbSet<Order> Orders { get; set; }    

    }
}
