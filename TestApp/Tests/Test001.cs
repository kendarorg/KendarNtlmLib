using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using KLib;

namespace TestApp.Tests
{
    class Test001
    {
        const string TYPE_1_MESSAGE = "NTLM TlRMTVNTUAABAAAAA7IAAAoACgApAAAACQAJACAAAABMSUdIVENJVFlVUlNBLU1JTk9S";
        const string TYPE_2_MESSAGE = "NTLM TlRMTVNTUAACAAAAAAAAACgAAAABggCgU3J2Tm9uY2UAAAAAAAAAAA==";
            //"NTLM TlRMTVNTUAACAAAAAAAAACgAAAABggAAU3J2Tm9uY2UAAAAAAAAAAA==";
        const string TYPE_3_MESSAGE = "NTLM TlRMTVNTUAADAAAAGAAYAHIAAAAYABgAigAAABQAFABAAAAADAAMAFQAAAASABI" +
            "AYAAAAAAAAACiAAAAAYIAAFUAUgBTAEEALQBNAEkATgBPAFIAWgBhAHAAaABvAGQATABJAEcASA" +
            "BUAEMASQBUAFkArYfKbe/jRoW5xDxHeoxC1gBmfWiS5+iX4OAN4xBKG/IFPwfH3agtPEia6YnhsADT";

        const string USER_NAME = "Zaphod";
        const string PASSWORD = "Beeblebrox";
        const string DOMAIN = "Ursa-Minor";
        const string HOST = "LightCity";

        static string ReceiveType1Message()
        {
            return TYPE_1_MESSAGE;
        }

        static void SendType2Message(string type2message)
        {
            if (TYPE_2_MESSAGE != type2message)
            {
                throw new Exception("Wrong type 2 message");
            }
        }

        static string ReceiveType3Message()
        {
            return TYPE_3_MESSAGE;
        }

        public static void Execute()
        {
            var ntlmManager = new KendarNtlmNet("SrvNonce");

            //Receive type
            var type1messageFromClient = ReceiveType1Message();

            var type2messageForClient = "NTLM " + ntlmManager.SetupChallenge(type1messageFromClient.Substring(5));
            SendType2Message(type2messageForClient);

            var type3messageFromClient = ReceiveType3Message();
            ntlmManager.ReadResponse(type3messageFromClient.Substring(5));
            if (!ntlmManager.VerifyResponse(PASSWORD))
            {
                throw new Exception("Invalid credentials");
            }

            if (ntlmManager.User != USER_NAME) throw new Exception("Invalid username");
            if (ntlmManager.Domain != DOMAIN.ToUpperInvariant()) throw new Exception("Invalid domain");
            if (ntlmManager.Host != HOST.ToUpperInvariant()) throw new Exception("Invalid host");

            Console.WriteLine("Success!!");
        }
    }
}
