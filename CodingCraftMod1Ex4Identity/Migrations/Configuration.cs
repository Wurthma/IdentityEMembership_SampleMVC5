namespace CodingCraftMod1Ex4Identity.Migrations
{
    using CodingCraftMod1Ex4Identity.Models;
    using Microsoft.AspNet.Identity;
    using Microsoft.AspNet.Identity.EntityFramework;
    using Microsoft.Owin;
    using System;
    using System.Data.Entity;
    using System.Data.Entity.Migrations;
    using System.Linq;
    using System.Security.Claims;
    using System.Web.Configuration;

    internal sealed class Configuration : DbMigrationsConfiguration<CodingCraftMod1Ex4Identity.Models.Context>
    {
        public Configuration()
        {
            AutomaticMigrationsEnabled = true;
            AutomaticMigrationDataLossAllowed = true;
        }

        protected override void Seed(Context context)
        {
            //  This method will be called after migrating to the latest version.

            //  You can use the DbSet<T>.AddOrUpdate() helper extension method 
            //  to avoid creating duplicate seed data. E.g.
            //
            //    context.People.AddOrUpdate(
            //      p => p.FullName,
            //      new Person { FullName = "Andrew Peters" },
            //      new Person { FullName = "Brice Lambson" },
            //      new Person { FullName = "Rowan Miller" }
            //    );
            //

            var roleStore = new RoleStore<IdentityRole>(context);
            var roleManager = new RoleManager<IdentityRole>(roleStore);
            var userStore = new UserStore<Usuario>(context);
            var userManager = new UserManager<Usuario>(userStore);
            //Cria um usuário admin para aplicação
            var user = new Usuario {
                UserName = WebConfigurationManager.AppSettings["ApplicationEmail"],
                Email = WebConfigurationManager.AppSettings["ApplicationEmail"],
                EmailConfirmed = true };
            userManager.Create(user, WebConfigurationManager.AppSettings["ApplicationEmailPassword"]);

            //Adiciona roles padrões da aplicação
            roleManager.Create(new IdentityRole { Name = "Admin" });
            userManager.AddToRole(user.Id, "Admin");
            roleManager.Create(new IdentityRole { Name = "Premium" });
            userManager.AddToRole(user.Id, "Premium");
            roleManager.Create(new IdentityRole { Name = "Desenvolvedor" });
            userManager.AddToRole(user.Id, "Desenvolvedor");

            //Adiciona os Claims padrões da aplicação
            userManager.AddClaim(user.Id, new Claim(ClaimTypes.Role, "Premium"));
            userManager.AddClaim(user.Id, new Claim(ClaimTypes.Role, "Desenvolvedor"));
            userManager.AddClaim(user.Id, new Claim(ClaimTypes.Role, "Admin"));
            userManager.AddClaim(user.Id, new Claim(ClaimTypes.Email, user.Email));
        }
    }
}
