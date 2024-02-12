using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace AuthJwt.Controllers
{
 
    [ApiController]
    //[Authorize]
    public class CustomerController : ControllerBase
    {
        [HttpGet("GetCustomers")]
        public async Task<IActionResult> GetAllCustomers()
        {
            return Ok(new List<string>() { "Customer1", "Customer2" });
        }
    }
}
