using CodingCraftMod1Ex4Auth.Models;
using CodingCraftMod1Ex4Auth.ViewModels;
using System;
using System.Linq;
using System.Transactions;
using System.Web.Mvc;
using System.Web.Security;
using WebMatrix.WebData;
using CodingCraftMod1Ex4Auth.Infrastructure.Membership;

namespace CodingCraftMod1Ex4Auth.Controllers
{
    public class ContaController : Controller
    {
        private CodingCraftMod1Ex4AuthMembershipContext db = new CodingCraftMod1Ex4AuthMembershipContext();

        // GET: Conta
        public ActionResult Index()
        {
            return View();
        }

        //
        // GET: /Account/Login

        [AllowAnonymous]
        public ActionResult Login(string returnUrl)
        {
            ViewBag.ReturnUrl = returnUrl;
            return View();
        }

        //
        // POST: /Account/Login

        [HttpPost]
        [AllowAnonymous]
        public ActionResult Login(LoginViewModel model, string returnUrl)
        {
            if (ModelState.IsValid && WebSecurity.Login(model.UserName, model.Password, persistCookie: model.RememberMe))
            {
                FormsAuthentication.SetAuthCookie(model.UserName, false);
                return RedirectToAction("Index", "Home");
            }

            // If we got this far, something failed, redisplay form
            ModelState.AddModelError("", "O usuário ou senha informados estão incorretos.");
            return View(model);
        }

        //
        // POST: /Account/LogOff

        [HttpPost]
        public ActionResult LogOff()
        {
            WebSecurity.Logout();

            return RedirectToAction("Index", "Home");
        }

        //
        // GET: /Account/Register

        [AllowAnonymous]
        public ActionResult Register()
        {
            return View();
        }

        //
        // POST: /Account/Register

        [HttpPost]
        [AllowAnonymous]
        public ActionResult Register(RegisterViewModel model)
        {
            if (ModelState.IsValid)
            {
                // Attempt to register the user
                try
                {
                    using (var scope = new TransactionScope())
                    {
                        var usernameCreationStatus = WebSecurity.CreateUserAndAccount(model.UserName, model.Password,
                            propertyValues: new
                            {
                                CustomUserId = Guid.NewGuid(),
                                Suspended = false,
                                Points = 0
                            }, requireConfirmationToken: false);

                        WebSecurity.Login(model.UserName, model.Password);

                        scope.Complete();
                    }
                    return RedirectToAction("Index", "Home");
                }
                catch (MembershipCreateUserException e)
                {
                    ModelState.AddModelError("", ErrorCodeToString(e.StatusCode));
                }
            }

            // If we got this far, something failed, redisplay form
            return View(model);
        }

        public ActionResult Manage()
        {
            ManageViewModel manageUser = new ManageViewModel();
            var user = db.Memberships.Where(u => u.CustomUser.Name == System.Web.HttpContext.Current.User.Identity.Name).SingleOrDefault();
            manageUser.UserName = user.CustomUser.Name;
            return View(manageUser);
        }

        [HttpPost]
        public ActionResult Manage(ManageViewModel manageUser)
        {
            if (ModelState.IsValid)
            {
                if(manageUser.Password == manageUser.ConfirmPassword)
                {
                    var user = db.Memberships.Where(u => u.CustomUser.Name == System.Web.HttpContext.Current.User.Identity.Name).SingleOrDefault();
                    CustomMembershipProvider membershipProvider = new CustomMembershipProvider();
                    if(membershipProvider.ChangePassword(System.Web.HttpContext.Current.User.Identity.Name, manageUser.OldPassword, manageUser.Password))
                    {
                        TempData["AlteracaoSucesso"] = "Dados alterados com sucesso.";
                    }
                    else
                    {
                        ModelState.AddModelError(String.Empty, "A senha atual está incorreta.");
                    }
                }
                else
                {
                    ModelState.AddModelError(String.Empty, "A senha e a confirmação da senha não iguais.");
                    
                }
                return View(manageUser);
            }
            else
            {
                ModelState.AddModelError(String.Empty, "Ocorreu um erro ao tentar alterar os dados da sua conta.");
                return View(manageUser);
            }
        }

        #region Helpers
        private ActionResult RedirectToLocal(string returnUrl)
        {
            if (Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }
            else
            {
                return RedirectToAction("Index", "Home");
            }
        }

        public enum ManageMessageId
        {
            ChangePasswordSuccess,
            SetPasswordSuccess,
            RemoveLoginSuccess,
        }

        internal class ExternalLoginResult : ActionResult
        {
            public ExternalLoginResult(string provider, string returnUrl)
            {
                Provider = provider;
                ReturnUrl = returnUrl;
            }

            public string Provider { get; private set; }
            public string ReturnUrl { get; private set; }

            public override void ExecuteResult(ControllerContext context)
            {
                // OAuthWebSecurity.RequestAuthentication(Provider, ReturnUrl);
            }
        }

        private static string ErrorCodeToString(MembershipCreateStatus createStatus)
        {
            // See http://go.microsoft.com/fwlink/?LinkID=177550 for
            // a full list of status codes.
            switch (createStatus)
            {
                case MembershipCreateStatus.DuplicateUserName:
                    return "User name already exists. Please enter a different user name.";

                case MembershipCreateStatus.DuplicateEmail:
                    return "A user name for that e-mail address already exists. Please enter a different e-mail address.";

                case MembershipCreateStatus.InvalidPassword:
                    return "The password provided is invalid. Please enter a valid password value.";

                case MembershipCreateStatus.InvalidEmail:
                    return "The e-mail address provided is invalid. Please check the value and try again.";

                case MembershipCreateStatus.InvalidAnswer:
                    return "The password retrieval answer provided is invalid. Please check the value and try again.";

                case MembershipCreateStatus.InvalidQuestion:
                    return "The password retrieval question provided is invalid. Please check the value and try again.";

                case MembershipCreateStatus.InvalidUserName:
                    return "The user name provided is invalid. Please check the value and try again.";

                case MembershipCreateStatus.ProviderError:
                    return "The authentication provider returned an error. Please verify your entry and try again. If the problem persists, please contact your system administrator.";

                case MembershipCreateStatus.UserRejected:
                    return "The user creation request has been canceled. Please verify your entry and try again. If the problem persists, please contact your system administrator.";

                default:
                    return "An unknown error occurred. Please verify your entry and try again. If the problem persists, please contact your system administrator.";
            }
        }
        #endregion
    }
}