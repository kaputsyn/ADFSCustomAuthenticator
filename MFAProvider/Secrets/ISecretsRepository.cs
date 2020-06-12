using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MFAProvider.Secrets
{
    interface ISecretsRepository
    {
        Task PutSecret(string upn, string secret);
        Task<string> GetSecret(string upd);
    }
}
