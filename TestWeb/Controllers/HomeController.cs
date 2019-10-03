using System.Web.Mvc;
using TestWeb.Lib;

namespace TestWeb.Controllers
{
	public class HomeController : Controller
	{
		[NtlmAuthorize]
		public ActionResult Index()
		{
			return new EmptyResult();
		}

		public ActionResult About()
		{
			return View();
		}
	}
}
