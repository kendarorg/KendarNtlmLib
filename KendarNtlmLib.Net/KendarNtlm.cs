using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices;
using KLib;


namespace KLib
{
	public class KendarNtlmNet
	{
		public string Nonce { get; private set; }
		public string TargetDomain { get; private set; }
		public string TargetServer { get; private set; }
		public string User { get; private set; }
		public string Domain { get; private set; }
		public string Host { get; private set; }

		private IntPtr _handle;
		private KendarNtlmLib _manager;
		public KendarNtlmNet(string nonce,string targetDomain = "",string targetServer ="")
		{
			if (nonce.Length < 8)
			{
				nonce = nonce.PadRight(8, ' ');
			}
			else if (nonce.Length > 8)
			{
				nonce = nonce.Substring(0, 8);
			}
			Nonce = nonce;
			TargetDomain = targetDomain;
			TargetServer = targetServer;

			unsafe
			{
				byte[] nonceTmp = Encoding.ASCII.GetBytes(Nonce);
				byte[] targetDomainTmp = Encoding.Unicode.GetBytes(TargetDomain);
				byte[] targetServerTmp = Encoding.Unicode.GetBytes(TargetServer);
				fixed (byte* nonceFix = nonceTmp)
				{
					fixed (byte* targetDomainFix = targetDomainTmp)
					{
						fixed (byte* targetServerFix = targetServerTmp)
						{

							_manager = new KendarNtlmLib(nonceFix, targetDomainFix, targetDomainTmp.Length, targetServerFix, targetServerTmp.Length);
						}
					}
				}
			}
		}

		public bool VerifyResponse(string password)
		{
			var toret = false;
			unsafe
			{
				byte[] outtmp = Encoding.ASCII.GetBytes(password);
				fixed (byte* output = outtmp)
				{
					toret = _manager.VerifyPassword(output, outtmp.Length);
				}
			}
			return toret;
		}

		public void ReadResponse(string type3message)
		{
			unsafe
			{
				byte[] input = Convert.FromBase64String(type3message);
				fixed (byte* ptrType3Msg = input)
				{
					_manager.InitializeLastMessage((byte*)ptrType3Msg, input.Length);
				}

				//User length/user
				int len = _manager.ReadUserData((byte)'U', null, 0);
				byte[] output = new byte[len];
				fixed (byte* userData = input)
				{
					_manager.ReadUserData((byte)'U', userData, len);
					userData[len] = 0;
					User = Encoding.Unicode.GetString(input);
					User = User.Substring(0, len / 2);
				}

				//Host length/host
				len = _manager.ReadUserData((byte)'H', null, 0);
				output = new byte[len];
				fixed (byte* userData = input)
				{
					_manager.ReadUserData((byte)'H', userData, len);
					userData[len] = 0;
					Host = Encoding.Unicode.GetString(input);
					Host = Host.Substring(0, len / 2);
				}

				//Domain length/domain
				len = _manager.ReadUserData((byte)'D', null, 0);
				output = new byte[len];
				fixed (byte* userData = input)
				{
					_manager.ReadUserData((byte)'D', userData, len);
					userData[len] = 0;
					Domain = Encoding.Unicode.GetString(input);
					Domain = Domain.Substring(0, len / 2);
				}
			};
		}

        public void ReadFirstResponse(string type2message)
        {
            unsafe
            {
                byte[] outtmp = Convert.FromBase64String(type2message);
                fixed (byte* output = outtmp)
                {
                    _manager.ReadFirstResponse(output, outtmp.Length);
                }
            }
        }

		public string SetupChallenge(string type1message)
		{
			string base64response = null;
			unsafe
			{
				byte[] input = Convert.FromBase64String(type1message);

				fixed (byte* ptrType1Msg = input)
				{
					var lenType2Msg = _manager.PrepareFirstResponse((byte*)ptrType1Msg, input.Length, null, 0);

					byte[] output = new byte[lenType2Msg];
					fixed (byte* ptrType2Msg = output)
					{
						lenType2Msg = _manager.PrepareFirstResponse(
								ptrType1Msg, input.Length, ptrType2Msg, lenType2Msg);
						base64response = Convert.ToBase64String(output, 0, lenType2Msg, Base64FormattingOptions.None);
					}
				}
			}
			return base64response;
		}


	}
}
