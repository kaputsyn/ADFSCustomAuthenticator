using Microsoft.IdentityServer.Web.Authentication.External;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MFAProvider
{
    class FozzyAuthenticationAdapterMetadata : IAuthenticationAdapterMetadata
    {
        //Returns the name of the provider that will be shown in the AD FS management UI (not visible to end users)
        public string AdminName
        {
            get { return "My Example MFA Adapter"; }
        }

        //Returns an array of strings containing URIs indicating the set of authentication methods implemented by the adapter 
        /// AD FS requires that, if authentication is successful, the method actually employed will be returned by the
        /// final call to TryEndAuthentication(). If no authentication method is returned, or the method returned is not
        /// one of the methods listed in this property, the authentication attempt will fail.
        public virtual string[] AuthenticationMethods
        {
            get { return new[] { "http://schemas.microsoft.com/ws/2008/06/identity/authenticationmethod/hardwaretoken" }; }
        }

        /// Returns an array indicating which languages are supported by the provider. AD FS uses this information
        /// to determine the best language\locale to display to the user.
        public int[] AvailableLcids
        {
            get
            {
                return new[] { new CultureInfo("en-us").LCID};
            }
        }

        /// Returns a Dictionary containing the set of localized friendly names of the provider, indexed by lcid. 
        /// These Friendly Names are displayed in the "choice page" offered to the user when there is more than 
        /// one secondary authentication provider available.
        public Dictionary<int, string> FriendlyNames
        {
            get
            {
                Dictionary<int, string> _friendlyNames = new Dictionary<int, string>();
                _friendlyNames.Add(new CultureInfo("en-us").LCID, "Friendly name of My Example MFA Adapter for end users (en)");
                _friendlyNames.Add(new CultureInfo("fr").LCID, "Friendly name translated to fr locale");
                return _friendlyNames;
            }
        }

        /// Returns a Dictionary containing the set of localized descriptions (hover over help) of the provider, indexed by lcid. 
        /// These descriptions are displayed in the "choice page" offered to the user when there is more than one 
        /// secondary authentication provider available.
        public Dictionary<int, string> Descriptions
        {
            get
            {
                Dictionary<int, string> _descriptions = new Dictionary<int, string>();
                _descriptions.Add(new CultureInfo("en-us").LCID, "Description of My Example MFA Adapter for end users (en)");
                _descriptions.Add(new CultureInfo("fr").LCID, "Description translated to fr locale");
                return _descriptions;
            }
        }

        /// Returns an array indicating the type of claim that the adapter uses to identify the user being authenticated.
        /// Note that although the property is an array, only the first element is currently used.
        /// MUST BE ONE OF THE FOLLOWING
        /// "https://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname"
        /// "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn"
        /// "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"
        /// "https://schemas.microsoft.com/ws/2008/06/identity/claims/primarysid"
        public string[] IdentityClaims
        {
            get { return new[] { "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn" }; }
        }

        //All external providers must return a value of "true" for this property.
        public bool RequiresIdentity
        {
            get { return true; }
        }
    }
}
