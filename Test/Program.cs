using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Test
{
    class Program
    {
        static void Main(string[] args)
        {
            var secret
                = "7ZNRTPBQAVSJRAUM";
            //= CodeManager.GenerateSecretKey();

            var code = "531948";
            var authenticator = new TwoStepsAuthenticator.TimeAuthenticator();
            bool isok = authenticator.CheckCode(secret, code, user:null);

        }
    }
}
