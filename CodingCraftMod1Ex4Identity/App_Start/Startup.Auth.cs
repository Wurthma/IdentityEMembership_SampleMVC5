using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
using Microsoft.Owin.Security.Cookies;
using CodingCraftMod1Ex4Identity.Models;
using Owin;
using System;
using System.Web.Configuration;
using Microsoft.Owin.Security.Facebook;
using Owin.Security.Providers.StackExchange;

namespace IdentitySample
{
    public partial class Startup
    {
        // For more information on configuring authentication, please visit http://go.microsoft.com/fwlink/?LinkId=301864
        public void ConfigureAuth(IAppBuilder app)
        {
            // Configure the db context, user manager and role manager to use a single instance per request
            app.CreatePerOwinContext(Context.Create);
            app.CreatePerOwinContext<ApplicationUserManager>(ApplicationUserManager.Create);
            app.CreatePerOwinContext<ApplicationRoleManager>(ApplicationRoleManager.Create);
            app.CreatePerOwinContext<ApplicationSignInManager>(ApplicationSignInManager.Create);

            // Enable the application to use a cookie to store information for the signed in user
            // and to use a cookie to temporarily store information about a user logging in with a third party login provider
            // Configure the sign in cookie
            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = DefaultAuthenticationTypes.ApplicationCookie,
                LoginPath = new PathString("/Account/Login"),
                Provider = new CookieAuthenticationProvider
                {
                    // Enables the application to validate the security stamp when the user logs in.
                    // This is a security feature which is used when you change a password or add an external login to your account.  
                    OnValidateIdentity = SecurityStampValidator.OnValidateIdentity<ApplicationUserManager, Usuario>(
                        validateInterval: TimeSpan.FromMinutes(30),
                        regenerateIdentity: (manager, user) => user.GenerateUserIdentityAsync(manager))
                },
                CookieName = "IdentitySampleApplication",
                CookiePath = "/"
            });
            app.UseExternalSignInCookie(DefaultAuthenticationTypes.ExternalCookie);

            // Enables the application to temporarily store user information when they are verifying the second factor in the two-factor authentication process.
            app.UseTwoFactorSignInCookie(DefaultAuthenticationTypes.TwoFactorCookie, TimeSpan.FromMinutes(5));

            // Enables the application to remember the second login verification factor such as phone or email.
            // Once you check this option, your second step of verification during the login process will be remembered on the device where you logged in from.
            // This is similar to the RememberMe option when you log in.
            app.UseTwoFactorRememberBrowserCookie(DefaultAuthenticationTypes.TwoFactorRememberBrowserCookie);

            //Acesse esse link para um tutorial sobre várias APIs de autenticação: https://docs.microsoft.com/pt-br/aspnet/web-api/overview/security/external-authentication-services
            app.UseMicrosoftAccountAuthentication(
                clientId: WebConfigurationManager.AppSettings["MSclientId"],
                clientSecret: WebConfigurationManager.AppSettings["MSclientSecret"]);

            app.UseTwitterAuthentication(
               consumerKey: WebConfigurationManager.AppSettings["consumerKey"],
               consumerSecret: WebConfigurationManager.AppSettings["consumerSecret"]);
            //https://stackoverflow.com/questions/25011890/owin-twitter-login-the-remote-certificate-is-invalid-according-to-the-validati


            //https://docs.microsoft.com/en-us/aspnet/core/security/authentication/social/facebook-logins?view=aspnetcore-2.2
            var options = new FacebookAuthenticationOptions
            {
                AppId = WebConfigurationManager.AppSettings["appId"],
                AppSecret = WebConfigurationManager.AppSettings["appSecret"],
            };
            options.Scope.Add("public_profile");
            options.Scope.Add("email");

            //add this for facebook to actually return the email and name
            //https://stackoverflow.com/questions/32059384/why-new-fb-api-2-4-returns-null-email-on-mvc-5-with-identity-and-oauth-2
            options.Fields.Add("email");
            options.Fields.Add("name");

            app.UseFacebookAuthentication(options);

            //https://docs.microsoft.com/en-us/aspnet/mvc/overview/security/create-an-aspnet-mvc-5-app-with-facebook-and-google-oauth2-and-openid-sign-on
            app.UseGoogleAuthentication(
                clientId: WebConfigurationManager.AppSettings["GoogClientID"],
                clientSecret: WebConfigurationManager.AppSettings["GoogClientSecret"]);

            //Autenticação com o stackexchange
            StackExchangeAuthenticationExtensions.UseStackExchangeAuthentication(app,
                new StackExchangeAuthenticationOptions
                {
                    ClientId = WebConfigurationManager.AppSettings["StackClientId"],
                    ClientSecret = WebConfigurationManager.AppSettings["StackClientSecret"],
                    Key = WebConfigurationManager.AppSettings["StackKey"]
                });
        }
    }
}