using CodingCraftMod1Ex4Auth.Migrations;
using System.Data.Entity;

namespace CodingCraftMod1Ex4Auth.Models
{
    public class CodingCraftMod1Ex4AuthMembershipContext : DbContext
    {
        public CodingCraftMod1Ex4AuthMembershipContext() : base("DefaultConnection")
        {
            Database.SetInitializer(new CreateDatabaseIfNotExists<CodingCraftMod1Ex4AuthMembershipContext>());
            //Database.SetInitializer<SchoolDBContext>(new DropCreateDatabaseIfModelChanges<SchoolDBContext>());
            //Database.SetInitializer<SchoolDBContext>(new DropCreateDatabaseAlways<SchoolDBContext>());
            //Database.SetInitializer(new DbInitializer());
        }

        public DbSet<CustomUser> CustomUsers { get; set; }
        public DbSet<Membership> Memberships { get; set; }
        public DbSet<Role> Roles { get; set; }
        public DbSet<UserRole> UserRoles { get; set; }
    }
}