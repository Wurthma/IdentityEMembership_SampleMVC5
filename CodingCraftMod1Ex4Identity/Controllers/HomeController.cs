using System.Web.Mvc;

namespace CodingCraftMod1Ex4Identity.Controllers
{
    public class HomeController : Controller
    {
        [HttpGet]
        [Authorize]
        [RequireHttps]
        public ActionResult Index()
        {
            return View();
        }

        [HttpGet]
        [Authorize(Roles = "Premium")]
        public ActionResult About()
        {
            ViewBag.Message = "Site com exemplos do Microsoft Identity. Só é possível acessar está pagina tendo a role Premium";

            return View();
        }

        [HttpGet]
        [Authorize(Roles = "Desenvolvedor")]
        public ActionResult Contact()
        {
            ViewBag.Message = "Your contact page.";

            return View();
        }
    }
}
