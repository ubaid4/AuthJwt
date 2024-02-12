using AuthJwt.Interfaces;
using AuthJwt.Models;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace AuthJwt.Services
{
    public class JwtService : IJwt
    {
        private readonly IConfiguration _configuration;
        public JwtService(IConfiguration configuration) {
            _configuration = configuration;
        }
        public SignInResponce CreateJwtToken(AppUser User, List<string> Roles,IList<Claim> UserClaims, IList<Claim> RoleClaims)
        {
            DateTime expiration= DateTime.UtcNow.AddMinutes(Convert.ToDouble( _configuration.GetSection("Jwt")["Expiration_Minute"]));
            List<Claim> claims = new List<Claim>()
            {
                new Claim(JwtRegisteredClaimNames.NameId, User.Id.ToString()),
                new Claim(JwtRegisteredClaimNames.UniqueName, User.UserName),
            };


            foreach (var role in Roles)
            {
                claims.Add(new Claim(ClaimTypes.Role,role));
                
            }

            foreach (var userClaim in UserClaims)
            {
                claims.Add(userClaim);
            }

            foreach (var roleClaim in RoleClaims)
            {
                claims.Add(roleClaim);
            }


            SymmetricSecurityKey secKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration.GetSection("Jwt")["Key"]));

            SigningCredentials cred = new SigningCredentials(secKey, SecurityAlgorithms.HmacSha512Signature);


            // descriptor method
            SecurityTokenDescriptor descriptor = new SecurityTokenDescriptor()
            {
                Subject = new ClaimsIdentity(claims),
                Expires = expiration,
                SigningCredentials = cred,
                Issuer = _configuration.GetSection("Jwt")["Issuer"],
                Audience= _configuration.GetSection("Jwt")["Audience"],

            };

            JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
            var tokenGen = handler.CreateToken(descriptor);
            var token = handler.WriteToken(tokenGen);
            return new SignInResponce() { ExpirationTime = expiration, Phone = User.PhoneNumber, Token = token, UserName = User.UserName };
        }
    }
}
