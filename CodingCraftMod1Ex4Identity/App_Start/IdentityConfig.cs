using System.Security.Claims;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using System;
using System.Data.Entity;
using System.Threading.Tasks;
using System.Web;
using CodingCraftMod1Ex4Identity.Helpers;
using CodingCraftMod1Ex4Identity.ViewModels;
using CodingCraftMod1Ex4Identity.Models;
using System.Web.Configuration;

namespace CodingCraftMod1Ex4Identity.Models
{
    // Configure the application user manager used in this application. UserManager is defined in ASP.NET Identity and is used by the application.

    public class ApplicationUserManager : UserManager<Usuario>
    {
        public ApplicationUserManager(IUserStore<Usuario> store)
            : base(store)
        {
        }

        public static ApplicationUserManager Create(IdentityFactoryOptions<ApplicationUserManager> options,
            IOwinContext context)
        {
            var manager = new ApplicationUserManager(new UserStore<Usuario>(context.Get<Context>()));
            // Configure validation logic for usernames
            manager.UserValidator = new UserValidator<Usuario>(manager)
            {
                AllowOnlyAlphanumericUserNames = false,
                RequireUniqueEmail = true
            };
            // Configure validation logic for passwords
            manager.PasswordValidator = new PasswordValidator
            {
                RequiredLength = 6,
                RequireNonLetterOrDigit = false,
                RequireDigit = false,
                RequireLowercase = false,
                RequireUppercase = false,
            };
            // Configure user lockout defaults
            manager.UserLockoutEnabledByDefault = true;
            manager.DefaultAccountLockoutTimeSpan = TimeSpan.FromMinutes(5);
            manager.MaxFailedAccessAttemptsBeforeLockout = 5;
            // Register two factor authentication providers. This application uses Phone and Emails as a step of receiving a code for verifying the user
            // You can write your own provider and plug in here.
            manager.RegisterTwoFactorProvider("PhoneCode", new PhoneNumberTokenProvider<Usuario>
            {
                MessageFormat = "Seu código de segurança é: {0}"
            });
            manager.RegisterTwoFactorProvider("EmailCode", new EmailTokenProvider<Usuario>
            {
                Subject = "SecurityCode",
                BodyFormat = "Seu código de segurança é {0}"
            });
            manager.EmailService = new EmailService();
            manager.SmsService = new SmsService();
            var dataProtectionProvider = options.DataProtectionProvider;
            if (dataProtectionProvider != null)
            {
                manager.UserTokenProvider =
                    new DataProtectorTokenProvider<Usuario>(dataProtectionProvider.Create("ASP.NET Identity"));
            }
            return manager;
        }
    }

    // Configure the RoleManager used in the application. RoleManager is defined in the ASP.NET Identity core assembly
    public class ApplicationRoleManager : RoleManager<IdentityRole>
    {
        public ApplicationRoleManager(IRoleStore<IdentityRole,string> roleStore)
            : base(roleStore)
        {
        }

        public static ApplicationRoleManager Create(IdentityFactoryOptions<ApplicationRoleManager> options, IOwinContext context)
        {
            return new ApplicationRoleManager(new RoleStore<IdentityRole>(context.Get<Context>()));
        }
    }

    public class EmailService : IIdentityMessageService
    {
        public Task SendAsync(IdentityMessage message)
        {
            SendEmail envioEmail = new SendEmail();
            SendEmailViewModel email = new SendEmailViewModel{
                Origem = WebConfigurationManager.AppSettings["ApplicationEmail"],
                Destino = message.Destination,
                Assunto = message.Subject,
                Mensagem = message.Body,
                Usuario = WebConfigurationManager.AppSettings["SendGridUser"],
                Senha = WebConfigurationManager.AppSettings["SendGridPassword"],
                SmptHost = WebConfigurationManager.AppSettings["SendGridSmtpHost"],
                SmptPort = Convert.ToInt32(WebConfigurationManager.AppSettings["SendGridSmtpPort"])
            };
            envioEmail.Enviar(email, true);
            return Task.FromResult(0);
        }
    }

    public class SmsService : IIdentityMessageService
    {
        public Task SendAsync(IdentityMessage message)
        {
            // Plug in your sms service here to send a text message.
            return Task.FromResult(0);
        }
    }

    // This is useful if you do not want to tear down the database each time you run the application.
    // public class ApplicationDbInitializer : DropCreateDatabaseAlways<ApplicationDbContext>
    // This example shows you how to create a new database if the Model changes
    public class ApplicationDbInitializer : DropCreateDatabaseIfModelChanges<Context> 
    {
        protected override void Seed(Context context) {
            InitializeIdentityForEF(context);
            base.Seed(context);
        }

        //Create User=Admin@Admin.com with password=Admin@123456 in the Admin role        
        public static void InitializeIdentityForEF(Context db) {
            var userManager = HttpContext.Current.GetOwinContext().GetUserManager<ApplicationUserManager>();
            var roleManager = HttpContext.Current.GetOwinContext().Get<ApplicationRoleManager>();
            const string name = "admin@example.com";
            const string password = "Admin@123456";
            const string roleName = "Admin";

            //Create Role Admin if it does not exist
            var role = roleManager.FindByName(roleName);
            if (role == null) {
                role = new IdentityRole(roleName);
                var roleresult = roleManager.Create(role);
            }

            var user = userManager.FindByName(name);
            if (user == null) {
                user = new Usuario { UserName = name, Email = name };
                var result = userManager.Create(user, password);
                result = userManager.SetLockoutEnabled(user.Id, false);
            }

            // Add user admin to Role Admin if not already added
            var rolesForUser = userManager.GetRoles(user.Id);
            if (!rolesForUser.Contains(role.Name)) {
                var result = userManager.AddToRole(user.Id, role.Name);
            }
        }
    }

    public class ApplicationSignInManager : SignInManager<Usuario, string>
    {
        public ApplicationSignInManager(ApplicationUserManager userManager, IAuthenticationManager authenticationManager) : 
            base(userManager, authenticationManager) { }

        public override async Task<ClaimsIdentity> CreateUserIdentityAsync(Usuario user)
        {
            //Sempre que o usuário faz login adiciona por padrão a role User e o claim para e-mail
            //Esse claim é utilizado pelo Cookie. Não é adicionado ao BD.
            ClaimsIdentity claimIdentity = await base.CreateUserIdentityAsync(user);
            claimIdentity.AddClaim(new Claim(ClaimTypes.Email, user.Email));
            claimIdentity.AddClaim(new Claim(ClaimTypes.Role, "User"));
            return claimIdentity;
        }

        public static ApplicationSignInManager Create(IdentityFactoryOptions<ApplicationSignInManager> options, IOwinContext context)
        {
            return new ApplicationSignInManager(context.GetUserManager<ApplicationUserManager>(), context.Authentication);
        }
    }
}