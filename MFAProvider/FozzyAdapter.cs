﻿using MFAProvider.Secrets;
using Microsoft.IdentityServer.Web.Authentication.External;
using System;
using System.Diagnostics;
using System.Net;
using System.Security.Claims;
using System.Text;
using TwoStepsAuthenticator;

namespace MFAProvider
{
    public class FozzyAdapter : IAuthenticationAdapter
    {
        private readonly TimeAuthenticator _authenticator = new TimeAuthenticator();
        public IAuthenticationAdapterMetadata Metadata
        {
            get { return new FozzyAuthenticationAdapterMetadata(); }
        }

        public IAdapterPresentation BeginAuthentication(Claim identityClaim, HttpListenerRequest request, IAuthenticationContext authContext)
        {
            using (EventLog eventLog = new EventLog("MFAProvider"))
            {
                eventLog.Source = "MFAProvider";
                eventLog.WriteEntry($"BeginAuthentication {identityClaim.Value}", EventLogEntryType.Information, 101, 1);

                var secret = SqlSecretsRepository.GetSecret(identityClaim.Value).GetAwaiter().GetResult();
                authContext.Data.Add("upn", identityClaim.Value);
                if (String.IsNullOrEmpty(secret))
                {
                    eventLog.WriteEntry($"Secret not found {identityClaim.Value}", EventLogEntryType.Information, 102, 1);

                    secret = Authenticator.GenerateKey();
                    authContext.Data.Add("needSaveSecret", true);
                    authContext.Data.Add("secret", secret);
                    return new FozzyAdapterPresentationForm(secret, null);
                }
                else
                {
                    eventLog.WriteEntry($"Secret found {identityClaim.Value}", EventLogEntryType.Information, 103, 1);

                    authContext.Data.Add("needSaveSecret", false);
                    authContext.Data.Add("secret", secret);
                    return new FozzyAdapterPresentationForm(null, null);
                }

            }

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
            if (proofData == null || proofData.Properties == null || !proofData.Properties.ContainsKey("OTP"))
            {
                throw new ExternalAuthenticationException("Error - please input an answer", authContext);
            }

            var upn = (string)authContext.Data["upn"];
            var needSaveSecret = (bool)authContext.Data["needSaveSecret"];
            var secret = (string)authContext.Data["secret"];
            var otp = (string)proofData.Properties["OTP"];


            using (EventLog eventLog = new EventLog("MFAProvider"))
            {
                eventLog.Source = "FozzyAdapter";
                eventLog.WriteEntry($"TryEndAuthentication {(string)authContext.Data["upn"]}", EventLogEntryType.Information, 104, 1);



                var hasAttempts = SqlSecretsRepository.HasAttempt(upn).Result;
                var isValidOtp = ValidateProofData(otp, authContext);

                eventLog.WriteEntry($"Validate {upn} hasAttempts: {hasAttempts}  isValidOtp: {isValidOtp}", EventLogEntryType.Information, 106, 1);


                if (hasAttempts && isValidOtp)
                {

                    //authn complete - return authn method
                    outgoingClaims = new[]
                    {
                    new Claim( "http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationmethod",
                    "http://schemas.microsoft.com/ws/2008/06/identity/authenticationmethod/hardwaretoken" ) };

                    eventLog.WriteEntry($"Valid {upn}", EventLogEntryType.Information, 107, 1);

                    if (needSaveSecret)
                    {
                        eventLog.WriteEntry($"PutSecret {upn}", EventLogEntryType.Information, 105, 1);

                        SqlSecretsRepository.PutSecret(upn, secret).GetAwaiter().GetResult();
                    }
                    SqlSecretsRepository.UseAttempt(upn, otp, true).Wait();
                    return null;
                }
                SqlSecretsRepository.UseAttempt(upn, otp, false).Wait();
                eventLog.WriteEntry($"Not valid {upn}", EventLogEntryType.Information, 108, 1);
                //return new instance of IAdapterPresentationForm derived class
                outgoingClaims = new Claim[0];

                return new FozzyAdapterPresentationForm(needSaveSecret?secret:null,!hasAttempts?"Not enough attempts":"Invalid otp" );
            }
        }

        private bool ValidateProofData(string otp, IAuthenticationContext authContext)
        {

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
