using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using KLib;

namespace TestApp.Tests
{
    /// <summary>
    /// Fiddler intercepted GIT-IIS7
    /// </summary>
    class Test003
    {

        const string TYPE_1_MESSAGE = "NTLM TlRMTVNTUAABAAAAt4II4gAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==";
        const string TYPE_2_MESSAGE = "NTLM TlRMTVNTUAACAAAAHgAeADgAAAA1goriZKzWCm9cDlYAAAAAAAAAAJgAmAB"+
            "WAAAABgGxHQAAAA9XAEkATgAtAFEATgBLAFAAVABIADMASgBLADIAUAACAB4AVwBJAE4ALQBRAE4ASwBQAFQASAAzAEo"+
            "ASwAyAFAAAQAeAFcASQBOAC0AUQBOAEsAUABUAEgAMwBKAEsAMgBQAAQAHgBXAEkATgAtAFEATgBLAFAAVABIADMASgBLA"+
            "DIAUAADAB4AVwBJAE4ALQBRAE4ASwBQAFQASAAzAEoASwAyAFAABwAIAMJpYf4SLc4BAAAAAA==";
        //"NTLM TlRMTVNTUAACAAAAAAAAACgAAAABggAAU3J2Tm9uY2UAAAAAAAAAAA==";
        const string TYPE_3_MESSAGE = "NTLM TlRMTVNTUAADAAAAGAAYAGYAAAAgASABfgAAAAAAAABYAAAACAAIAFgAAAAGAAYAY"+
            "AAAABAAEACeAQAANYKI4gYBsR0AAAAPy+s4zfaNK7zNKbK/hbvH23UAcwBlAHIAVwBUAEwAAAAAAAAAAAAAAAAAAAAAAAAA" +
            "AAAAAAAAhc6UbNOpD/s7+lftB4Rd7AEBAAAAAAAAwmlh/hItzgEQ7zYcnuUIOwAAAAACAB4AVwBJAE4ALQBRAE4ASwBQAFQA" +
            "SAAzAEoASwAyAFAAAQAeAFcASQBOAC0AUQBOAEsAUABUAEgAMwBKAEsAMgBQAAQAHgBXAEkATgAtAFEATgBLAFAAVABIADMASg" +
            "BLADIAUAADAB4AVwBJAE4ALQBRAE4ASwBQAFQASAAzAEoASwAyAFAABwAIAMJpYf4SLc4BBgAEAAIAAAAIADAAMAAAAAAAAAABAA" +
            "AAACAAAPKrILOQ/lDAkANPW4mHwuBbjCzI0QdeGwz+6g9fnlq9CgAQAAAAAAAAAAAAAAAAAAAAAAAJAAAAAAAAAAAAAAAAAAAANbj" +
            "D+IEaVRmSOLuQg6jKCA==";

        const string USER_NAME = "user";
        const string PASSWORD = "password";
        const string DOMAIN = "WTL";
        const string HOST = "WTL";

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

            ntlmManager.ReadFirstResponse(TYPE_2_MESSAGE.Substring(5));
            var type2messageForClient = "NTLM " + ntlmManager.SetupChallenge(type1messageFromClient.Substring(5));
            //SendType2Message(type2messageForClient);

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
