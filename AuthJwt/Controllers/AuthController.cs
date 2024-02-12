using AuthJwt.Interfaces;
using AuthJwt.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.ComponentModel.DataAnnotations;
using System.Security.Claims;

namespace AuthJwt.Controllers
{
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<AppUser> UserManager;
        private readonly RoleManager<AppRole> RoleManager;
        private readonly SignInManager<AppUser> SignInManager;
        private readonly IJwt JwtHelper;

        public AuthController(
            UserManager<AppUser> _userManager,
            RoleManager<AppRole> _roleManager,
            SignInManager<AppUser> _signinManager,
            IJwt _jwtHelper

            )
        {
            UserManager = _userManager;
            RoleManager = _roleManager;
            SignInManager = _signinManager;
            JwtHelper = _jwtHelper;
        }
        [HttpPost("SignUp")]
        public async Task<ActionResult> SignUp(SignupDTO data)
        {
            var newUser = new AppUser() { UserName = data.UserName, Email = data.Email, PhoneNumber = data.PhoneNumber, PersonalName = data.UserName };
            IdentityResult res = await UserManager.CreateAsync(newUser, data.Password);
           
            if (!res.Succeeded)
            {
                return BadRequest(res.Errors);
            }
            var token=await UserManager.GenerateEmailConfirmationTokenAsync(newUser);
            return Ok(new { message="Please verify you email by link sent to your email", token });
        }

        [HttpGet("resendEmailVerification")]
        public async Task<IActionResult> resendEmailVerification(string UserName)
        {
            AppUser user = await UserManager.FindByNameAsync(UserName);
            if (user == null)
            {
                return NotFound("User Not found");
            }
            var token = await UserManager.GenerateEmailConfirmationTokenAsync(user);
            //send email with token, for example
            //emailService.SendEmail(user.Email,token);

            return Ok(new {message="Email verification link sent to you mail: "+user.Email ,token });
        }


        [HttpGet("VerifyUserEmail")]
        public async Task<IActionResult> verifyEmail(string UserName, string Token)
        {
            AppUser user = await UserManager.FindByNameAsync(UserName);
            IdentityResult result=await UserManager.ConfirmEmailAsync(user, Token);
            if (!result.Succeeded)
            {
                return BadRequest(result.Errors);
            }
            return Ok("Email verified successfully");
          
           
        }



        [HttpPost("SignIn")]
        public async Task<ActionResult> UserSignIn(SigninDTO data)
        {
            AppUser user = await UserManager.FindByNameAsync(data.UserName);

            if (user == null)
            {
                return BadRequest("Invalid user Name");
            }

            Microsoft.AspNetCore.Identity.SignInResult result = await SignInManager.PasswordSignInAsync(user, data.Password, false, true);
            if (result.IsLockedOut)
            {
                return BadRequest("your account is locked for 1 minutes");
            }
            if (result.IsNotAllowed)
            {
                return BadRequest("your account is not allowed to login");
            }
            if (!result.Succeeded)
            {
                return BadRequest("invalid password");

            }


            var roles = await UserManager.GetRolesAsync(user);
            List<string> rolesList = roles.ToList();

           IList<Claim> UserClaims = await UserManager.GetClaimsAsync(user);
           IList<Claim> RoleClaimsList= new List<Claim>();
            foreach (var role in rolesList)
            {
                AppRole roleObj = await RoleManager.FindByNameAsync(role);
                var roleClaims = await RoleManager.GetClaimsAsync(roleObj);
                foreach (var claim in roleClaims)
                {
                    RoleClaimsList.Add(claim);
                }
             
            };

            SignInResponce res = JwtHelper.CreateJwtToken(user, rolesList, UserClaims, RoleClaimsList);
            return Ok(res);
        }
        [HttpPost("AddRole")]
        public async Task<IActionResult> AddRole(string RoleName)
        {

            IdentityResult res = await RoleManager.CreateAsync(new AppRole() { Name = RoleName });
            if (!res.Succeeded)
            {
                return BadRequest(res.Errors);
            }
            return Ok(res);
        }

        [HttpGet("GetAllRoles")]
        public IActionResult getAllRoles()
        {
            return Ok(RoleManager.Roles.ToList());
        }

        [HttpPost("AddUserInRole")]
        public async Task<IActionResult> addUserInRole(UserRoleDTO data)
        {
            AppUser user = await UserManager.FindByNameAsync(data.UserName);
            if (user == null)
            {
                return BadRequest("User Not Exist");
            }

            IdentityResult res = await UserManager.AddToRoleAsync(user, data.RoleName);
            if (!res.Succeeded)
            {
                return BadRequest(res.Errors);
            }
            return Ok(res);

        }

        [HttpGet("getUserRoles")]
        public async Task<IActionResult> getUserRoles(string UserName)
        {
            AppUser user = await UserManager.FindByNameAsync(UserName);
            if (user == null)
            {
                return NotFound("User Not found");
            }
            var roles = await UserManager.GetRolesAsync(user);
            return Ok(roles);
        }
        [HttpDelete("RemoveUserFromRole")]
        public async Task<IActionResult> removeUserFromRole(UserRoleDTO data)
        {
            AppUser user = await UserManager.FindByNameAsync(data.UserName);
            if (user == null)
            {
                return NotFound("User Not found");
            }
            IdentityResult res = await UserManager.RemoveFromRoleAsync(user, data.RoleName);
            if (!res.Succeeded)
            {
                return BadRequest(res.Errors);
            }
            return Ok(res);
        }

        [HttpPut("ForgetPassword")]
        public async Task<ActionResult> forgetPasswordLink(string UserName)
        {
           AppUser user= await UserManager.FindByNameAsync(UserName);
            if (user == null)
            {
                return NotFound("User Not found");
            }
            string token=await UserManager.GeneratePasswordResetTokenAsync(user);
            //send email with token, for example
            //emailService.SendEmail(user.Email,token);

           return Ok("Here is password reset token: "+token);
        }
        
        [HttpPut("verifyForgetPassword")]
        public async Task<ActionResult> verifyLink(string UserName,string Token,string NewPassword)
        {
            AppUser appUser = await UserManager.FindByNameAsync(UserName);
            IdentityResult res= await UserManager.ResetPasswordAsync(appUser, Token, NewPassword);
            if (!res.Succeeded)
            {
                return BadRequest(res.Errors);
            }   

            return Ok("Password reset successfully");
        }

        /// <summary>
        /// it is simple way to reset password. if using it then no need to send token to email and verification.
        /// </summary>
        /// <param name="UserName"></param>
        /// <param name="OldPassword"></param>
        /// <param name="NewPassword"></param>
        /// <returns></returns>
        [HttpGet("resetPasswordSimple")]

        public async Task<ActionResult> resetPassword(string UserName,string OldPassword,string NewPassword)
        {
            AppUser appUser = await UserManager.FindByNameAsync(UserName);
            IdentityResult res = await UserManager.ChangePasswordAsync(appUser, OldPassword, NewPassword);
            if (!res.Succeeded)
            {
                return BadRequest(res.Errors);
            }
            return Ok("Password reset successfully");
        }
        /// <summary>
        /// it is email token verification way to reset password. if using it then need to send token to email and verification.
        /// </summary>
        [HttpGet("sendResetPasswordToken")]
        public async Task<ActionResult> sendResetPasswordToken(string UserName)
        {
            AppUser user = await UserManager.FindByNameAsync(UserName);
            if (user == null)
            {
                return NotFound("User Not found");
            }
            string token = await UserManager.GeneratePasswordResetTokenAsync(user);
            //send email with token, for example
            //emailService.SendEmail(user.Email,token)
            return Ok(new { message="reset password token sent to you mail",token });
        }
        [HttpGet("verifyResetPasswordToken")]
        public async Task<ActionResult> verifyResetPasswordToken(string UserName,string Token,string NewPassword)
        {
            AppUser appUser = await UserManager.FindByNameAsync(UserName);
            if (appUser == null)
            {
                   return NotFound("User Not found");
            }
            IdentityResult res = await UserManager.ResetPasswordAsync(appUser, Token, NewPassword);
            
            if (!res.Succeeded)
            {
                return BadRequest(res.Errors);
            }
            return Ok("Password reset successfully");
        }
        [HttpPut("AddUserClaim")]
        public async Task<IActionResult> AddUserClaim(string UserName, string ClaimType, string ClaimValue)
        {
            AppUser user = await UserManager.FindByNameAsync(UserName);
            if (user == null)
            {
                return NotFound("User Not found");
            }
            IdentityResult res = await UserManager.AddClaimAsync(user, new Claim(ClaimType, ClaimValue));
            if (!res.Succeeded)
            {
                return BadRequest(res.Errors);
            }
            return Ok(res);
        }
    

        [HttpGet("GetUserClaims")]
        public async Task<IActionResult> GetUserClaims(string UserName)
        {
            AppUser user = await UserManager.FindByNameAsync(UserName);
            if (user == null)
            {
                return NotFound("User Not found");
            }
            var claims = await UserManager.GetClaimsAsync(user);
            return Ok(claims);
        }


        [HttpDelete("RemoveUserClaim")]
        public async Task<IActionResult> RemoveUserClaim(string UserName, string ClaimType)
        {
            AppUser user = await UserManager.FindByNameAsync(UserName);
            if (user == null)
            {
                return NotFound("User Not found");
            }
            var claims=UserManager.GetClaimsAsync(user);
            Claim claim=claims.Result.Where(x=>x.Type==ClaimType).FirstOrDefault();
            if (claim==null)
            {
                return NotFound("Claim Not found");
            }   

           
            IdentityResult res = await UserManager.RemoveClaimAsync(user, claim);
            if (!res.Succeeded)
            {
                return BadRequest(res.Errors);
            }
            return Ok(res);
        }

        [HttpPut("AddRoleClaim")]
        public async Task<IActionResult> AddRoleClaim(string RoleName, string ClaimType, string ClaimValue)
        {
            AppRole role = await RoleManager.FindByNameAsync(RoleName);
            if (role == null)
            {
                return NotFound("Role Not found");
            }
            IdentityResult res = await RoleManager.AddClaimAsync(role, new Claim(ClaimType, ClaimValue));
            if (!res.Succeeded)
            {
                return BadRequest(res.Errors);
            }
            return Ok(res);
        }
        [HttpGet("GetRoleClaims")]
        public async Task<IActionResult> GetRoleClaims(string RoleName)
        {
            AppRole role = await RoleManager.FindByNameAsync(RoleName);
            if (role == null)
            {
                return NotFound("Role Not found");
            }
            var claims = await RoleManager.GetClaimsAsync(role);
            return Ok(claims);
        }
        

        [HttpDelete("RemoveRoleClaim")]
        public async Task<IActionResult> RemoveRoleClaim(string RoleName, string ClaimType)
        {
            AppRole role = await RoleManager.FindByNameAsync(RoleName);
            if (role == null)
            {
                return NotFound("Role Not found");
            }
            var claims=RoleManager.GetClaimsAsync(role);
            Claim claim=claims.Result.Where(x=>x.Type==ClaimType).FirstOrDefault();
            if (claim==null)
            {
                return NotFound("Claim Not found");
            }
            IdentityResult res = await RoleManager.RemoveClaimAsync(role, claim);
            if (!res.Succeeded)
            {
                return BadRequest(res.Errors);
            }
            return Ok(res);
        }
        
     
    }



    public class SignupDTO
    {
        public string Email { get; set; }
        public  string UserName { get; set;}
        public string Password { get; set;}
        public  string PhoneNumber { get; set;}


    }
    public class SigninDTO
    {
        [Required]
        public string UserName { get; set; }
        [Required]

        public string Password { get; set; }
    }
    public class UserRoleDTO
    {
        [Required]

        public string UserName { get; set; }
        [Required]
        public string RoleName { get; set; } 
    }
}
