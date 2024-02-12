using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AuthJwt.Controllers
{
    [ApiController]
    //[Authorize(Roles ="superadmin", AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
    [Authorize(Policy = "UbaidPolicy2")]
    public class OrderController : ControllerBase
    {
        [HttpGet("GetOrders")]
        public async Task<IActionResult> GetAllOrders()
        {
            return Ok( new List<string>() { "Order1", "order2" });
        }
        [HttpGet("GetOrder/{OrderId}")]
        public IActionResult GetOneOrder(string OrderId)
        {
            return Ok("Here is order of Id "+OrderId);
        }

    }
}
