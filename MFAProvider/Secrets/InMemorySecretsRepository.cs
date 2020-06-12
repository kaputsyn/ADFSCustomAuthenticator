using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MFAProvider.Secrets
{
    public class InMemorySecretsRepository 
    {
        private static readonly ConcurrentDictionary<string,string> secrets = new ConcurrentDictionary<string,string>();
        public static async Task<string> GetSecret(string upd)
        {
            string value;
            secrets.TryGetValue(upd, out value);

            return value;
        }

        public static async Task PutSecret(string upn, string secret)
        {
            secrets.TryAdd(upn, secret);
        }
    }
}
