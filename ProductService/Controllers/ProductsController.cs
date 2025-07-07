using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace E_Commerce.ProductService.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    //[Authorize]
    public class ProductsController : ControllerBase
    {
        [HttpGet]
        public ActionResult<List<string>> GetProducts()
        {
            List<string> Products = new List<string>();
            Products.Add("Product 1");
            Products.Add("Product 2");
            Products.Add("Product 3");
            Products.Add("Product 4");
            Products.Add("Product 5");
            Products.Add("Product 6");
            Products.Add("Product 7");
            Products.Add("Product 8");
            Products.Add("Product 9");
            Products.Add("Product 10");
            return Products.ToList();
        }
    };
}
