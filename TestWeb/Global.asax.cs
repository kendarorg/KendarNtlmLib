using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Web;
using System.Web.Mvc;
using System.Web.Routing;

namespace TestWeb
{
	// Note: For instructions on enabling IIS6 or IIS7 classic mode, 
	// visit http://go.microsoft.com/?LinkId=9394801

	public class MvcApplication : System.Web.HttpApplication
	{
		public static void RegisterGlobalFilters(GlobalFilterCollection filters)
		{
			filters.Add(new HandleErrorAttribute());
		}

		public static void RegisterRoutes(RouteCollection routes)
		{
			routes.IgnoreRoute("{resource}.axd/{*pathInfo}");


			routes.MapRoute(
				"Default",
				"{*url}",
				new { controller = "Home", action = "Index" }
				);

		}

		//This should be called with the names of the dlls
		private void RegisterDlls(params string[] dllNames)
		{
			AppDomain curDomain = AppDomain.CurrentDomain;
			//The directory must be present in two kinds in two subdirs of the website
			//at the same level of the "bin" directory:
			//binnative/x86 and binnative/x64
			String binDir = Path.Combine(curDomain.BaseDirectory, "bin_native", Environment.Is64BitProcess ? "x64" : "x86");
			String shadowCopyDir = curDomain.DynamicDirectory;

			foreach (var dllName in dllNames)
			{
				String dllSrc = Path.Combine(binDir, dllName + ".dll");
				String dllDst = Path.Combine(shadowCopyDir, Path.GetFileName(dllSrc));

				try
				{
					//The files are copied on the shadow copy areas
					File.Copy(dllSrc, dllDst, true);
					//And loaded explicitely!
					Assembly.LoadFrom(dllDst);
				}
				catch (System.Exception ex)
				{
				}
			}
		}

		protected void Application_Start()
		{
			AreaRegistration.RegisterAllAreas();

			RegisterGlobalFilters(GlobalFilters.Filters);
			RegisterRoutes(RouteTable.Routes);
			RegisterDlls("KendarNtlmLib","KendarNtlmLib.Net");
		}
	}
}