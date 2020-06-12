using MFAProvider.Secrets;
using Microsoft.IdentityServer.Web.Authentication.External;
using System;
using System.Net;
using System.Security.Claims;
using TwoStepsAuthenticator;

namespace MFAProvider
{
    public class FozzyAdapter : IAuthenticationAdapter
    {
        private readonly TimeAuthenticator _authenticator = new TimeAuthenticator();
        public IAuthenticationAdapterMetadata Metadata
        {
            //get { return new <instance of IAuthenticationAdapterMetadata derived class>; }
            get { return new FozzyAuthenticationAdapterMetadata(); }
        }

        public IAdapterPresentation BeginAuthentication(Claim identityClaim, HttpListenerRequest request, IAuthenticationContext authContext)
        {
            var secret = InMemorySecretsRepository.GetSecret(identityClaim.Value).GetAwaiter().GetResult();
            authContext.Data.Add("upn", identityClaim.Value);
            if (String.IsNullOrEmpty(secret))
            {
                secret = Authenticator.GenerateKey();
                authContext.Data.Add("needSaveSecret", true);
                authContext.Data.Add("secret", secret);
                return new FozzyAdapterPresentationForm(secret);
            }
            else 
            {
                authContext.Data.Add("needSaveSecret", false);
                authContext.Data.Add("secret", secret);
                return new FozzyAdapterPresentationForm(null);
            }

            

            //return new instance of IAdapterPresentationForm derived class

        }

        public bool IsAvailableForUser(Claim identityClaim, IAuthenticationContext authContext)
        {
            return true; //its all available for now
        }

        public void OnAuthenticationPipelineLoad(IAuthenticationMethodConfigData configData)
        {
            //this is where AD FS passes us the config data, if such data was supplied at registration of the adapter

        }

        public void OnAuthenticationPipelineUnload()
        {

        }

        public IAdapterPresentation OnError(HttpListenerRequest request, ExternalAuthenticationException ex)
        {
            //return new instance of IAdapterPresentationForm derived class
            return null;
        }

        public IAdapterPresentation TryEndAuthentication(IAuthenticationContext authContext, IProofData proofData, HttpListenerRequest request, out Claim[] outgoingClaims)
        {

            if ((bool)authContext.Data["needSaveSecret"] == true) 
            {
                InMemorySecretsRepository.PutSecret((string)authContext.Data["upn"], (string)authContext.Data["secret"]).GetAwaiter().GetResult();
            }

            if (ValidateProofData(proofData, authContext)) 
            {
                //authn complete - return authn method
                outgoingClaims = new[]
                {
                    new Claim( "http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationmethod",
                    "http://schemas.microsoft.com/ws/2008/06/identity/authenticationmethod/hardwaretoken" ) };

                return null;
            }

            //return new instance of IAdapterPresentationForm derived class
            outgoingClaims = new Claim[0];
            return new FozzyAdapterPresentationForm(null);
        }

        private bool ValidateProofData(IProofData proofData, IAuthenticationContext authContext)
        {
            if (proofData == null || proofData.Properties == null || !proofData.Properties.ContainsKey("OTP"))
            {
                throw new ExternalAuthenticationException("Error - please input an answer", authContext);
            }

            var otp = (string)proofData.Properties["OTP"];

            if (_authenticator.CheckCode((string)authContext.Data["secret"], otp, (string)authContext.Data["upn"]))
            {
                return true;
            }
            else
            {
                return false;
            }
        }

    }
}
