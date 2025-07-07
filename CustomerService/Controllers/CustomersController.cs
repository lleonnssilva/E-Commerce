using Microsoft.AspNetCore.Mvc;

namespace CustomerService.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    //[Authorize]
    public class CustomersController : ControllerBase
    {
        [HttpGet]
        public ActionResult<List<string>> GetCustomers()
        {
            List<string> Customer = new List<string>();
            Customer.Add("Customer 1");
            Customer.Add("Customer 2");
            Customer.Add("Customer 3");
            Customer.Add("Customer 4");
            Customer.Add("Customer 5");
            Customer.Add("Customer 6");
            Customer.Add("Customer 7");
            Customer.Add("Customer 8");
            Customer.Add("Customer 9");
            Customer.Add("Customer 10");
            return Customer.ToList();
        }
    }
}
