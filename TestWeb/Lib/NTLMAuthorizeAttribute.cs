
using System;
using System.Text;
using System.Web.Mvc;
using KLib;

namespace TestWeb.Lib
{
	public class NtlmAuthorizeAttribute : AuthorizeAttribute
	{
		public override void OnAuthorization(AuthorizationContext filterContext)
		{
			if (filterContext == null)
			{
				throw new ArgumentNullException("filterContext");
			}
			const string nonce = "SrvNonce";
			var context = filterContext.HttpContext;
			var ntlmManager = new KendarNtlmNet(nonce,"domain");

			if (context.Request.Headers["Authorization"] == null)
			{
				context.Response.Clear();
				context.Response.Headers.Add("WWW-Authenticate", "NTLM");
				context.Response.Headers.Add("Connection", "Keep-Alive");
				context.Response.StatusCode = 401;
				filterContext.Result = new EmptyResult();
				context.Response.End();
			}
			else if (context.Request.Headers["Authorization"] != null)
			{
				var auth = context.Request.Headers["Authorization"];
				if (auth.ToUpperInvariant().StartsWith("NTLM "))
				{
					var ntlmAuth = auth.Substring(5);
					var blob = Convert.FromBase64String(ntlmAuth);
					if (blob[8] == 0x01)
					{
						var type2Message = ntlmManager.SetupChallenge(ntlmAuth);
						context.Response.Clear();
						context.Response.Headers.Add("WWW-Authenticate", "NTLM " + type2Message);
                        context.Response.Headers.Add("Connection", "Keep-Alive");
						context.Response.StatusCode = 401;
						filterContext.Result = new EmptyResult();
						context.Response.End();
					}
					else if (blob[8] == 0x03)
					{
						ntlmManager.ReadResponse(ntlmAuth);
						var password = GetUserPassword(ntlmManager.User);
						if (ntlmManager.VerifyResponse(password))
						{
							context.Response.StatusCode = 200;
						}
						else 
						{
							//Switch to basic
							context.Response.Clear();
                            context.Response.Headers.Add("WWW-Authenticate", "Basic realm=\"Secure Area\"");
                            context.Response.Headers.Add("Connection", "Keep-Alive");
							context.Response.StatusCode = 401;
							filterContext.Result = new EmptyResult();
							context.Response.End();
						}
					}
				}
				else if (auth.ToUpperInvariant().StartsWith("BASIC "))
				{
					byte[] encodedDataAsBytes = Convert.FromBase64String(auth.Replace("Basic ", ""));
					string value = Encoding.ASCII.GetString(encodedDataAsBytes);
					string username = value.Substring(0, value.IndexOf(':'));
					string passwordReceived = value.Substring(value.IndexOf(':') + 1);
					var passwordExpected = GetUserPassword(username);
					if (passwordExpected == passwordReceived)
					{
						context.Response.StatusCode = 200;
					}
					else
					{
						filterContext.Result = new HttpStatusCodeResult(401);
					}
				}
			}
		}

		private string GetUserPassword(string user)
		{
			return user;
		}
	}
}