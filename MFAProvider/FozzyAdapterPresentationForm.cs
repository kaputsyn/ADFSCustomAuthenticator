using MFAProvider.Properties;
using Microsoft.IdentityServer.Web.Authentication.External;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MFAProvider
{
    class FozzyAdapterPresentationForm : IAdapterPresentationForm
    {
        string _secret;
        public FozzyAdapterPresentationForm(string secret)
        {
            _secret = secret;
        }
        /// Returns the HTML Form fragment that contains the adapter user interface. This data will be included in the web page that is presented
        /// to the cient.
        public string GetFormHtml(int lcid)
        {
            if (String.IsNullOrEmpty(_secret))
            {
                return Resources.LoginPage;
            }
            else 
            {
                return Resources.RegisterPage.Replace("%MFASecret%", _secret);
            }
        }

        /// Return any external resources, ie references to libraries etc., that should be included in 
        /// the HEAD section of the presentation form html. 
        public string GetFormPreRenderHtml(int lcid)
        {
            return null;
        }

        //returns the title string for the web page which presents the HTML form content to the end user
        public string GetPageTitle(int lcid)
        {
            return "Fozzy MFA Adapter";
        }
    }
}
