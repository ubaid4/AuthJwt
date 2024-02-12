using AuthJwt.Models;
using System.Security.Claims;

namespace AuthJwt.Interfaces
{
    public interface IJwt
    {
        SignInResponce CreateJwtToken(AppUser User , List<string> Roles,IList<Claim> UserClaims,IList<Claim> RoleClaims);
    }
}
