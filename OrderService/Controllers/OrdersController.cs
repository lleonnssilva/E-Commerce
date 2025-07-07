using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace E_Commerce.OrderService.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    //[Authorize]
    public class OrdersController : ControllerBase
    {
        [HttpGet]
        public ActionResult<List<string>> GetOrders()
        {
            List<string> Order = new List<string>();
            Order.Add("Order 1");
            Order.Add("Order 2");
            Order.Add("Order 3");
            Order.Add("Order 4");
            Order.Add("Order 5");
            Order.Add("Order 6");
            Order.Add("Order 7");
            Order.Add("Order 8");
            Order.Add("Order 9");
            Order.Add("Order 10");
            return Order.ToList();
        }
    }
}
