namespace CodingCraftMod1Ex4Auth.Migrations
{
    using CodingCraftMod1Ex4Auth.Infrastructure.Helpers;
    using Models;
    using System;
    using System.Data.Entity;
    using System.Data.Entity.Migrations;
    using System.Linq;
    using WebMatrix.WebData;

    internal sealed class Configuration : DbMigrationsConfiguration<CodingCraftMod1Ex4AuthMembershipContext>
    {
        public Configuration()
        {
            AutomaticMigrationsEnabled = true;
            AutomaticMigrationDataLossAllowed = true;
        }

        protected override void Seed(CodingCraftMod1Ex4AuthMembershipContext context)
        {
            string password = "h+V92o4VkQjWgegKgqwprJ2PUFU="; //PasswordsHelper.EncodePassword("123456", System.Web.Security.MembershipPasswordFormat.Hashed);

            var user = new CustomUser
            {
                CustomUserId = Guid.NewGuid(),
                Name = "admin@codingcraft.com.br",
                CreatedOn = DateTime.Now,
                LastModified = DateTime.Now
            };

            context.CustomUsers.Add(user);
            context.SaveChanges();

            var membership = new Membership
            {
                MembershipId = Guid.NewGuid(),
                CustomUser = user,
                Password = password,
                CreatedOn = DateTime.Now,
                LastModified = DateTime.Now,
            };

            context.Memberships.Add(membership);
            context.SaveChanges();

            //Role padrao do sistema
            var rolePadrao = new Role
            {
                RoleId = Guid.NewGuid(),
                Name = "Padrao",
                CreatedOn = DateTime.Now,
                LastModified = DateTime.Now
            };

            context.Roles.Add(rolePadrao);
            context.SaveChanges();

            //Role para admin
            var roleAdmin = new Role
            {
                RoleId = Guid.NewGuid(),
                Name = "Admin",
                CreatedOn = DateTime.Now,
                LastModified = DateTime.Now
            };

            context.Roles.Add(roleAdmin);
            context.SaveChanges();

            //Inserção do UserRole para o usuário admin do sistema
            var userRole = new UserRole
            {
                UserRoleId = Guid.NewGuid(),
                RoleId = roleAdmin.RoleId,
                CustomUserId = user.CustomUserId,
                CreatedOn = DateTime.Now,
                LastModified = DateTime.Now
            };

            context.UserRoles.Add(userRole);
            context.SaveChanges();
        }
    }
}
