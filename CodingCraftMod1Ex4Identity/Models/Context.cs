using CodingCraftMod1Ex4Identity.Models;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using System.Data.Entity;
using System.Security.Claims;
using System.Threading.Tasks;

namespace CodingCraftMod1Ex4Identity.Models
{
    public class Context : IdentityDbContext<Usuario>
    {
        public Context()
            : base("DefaultConnection", throwIfV1Schema: false)
        {
            //Utilizar em ambiente de produção
            //Database.SetInitializer(new CreateDatabaseIfNotExists<Context>());
            Database.SetInitializer<Context>(new ApplicationDbInitializer());
        }

        static Context()
        {
            // Set the database intializer which is run once during application start
            // This seeds the database with admin user credentials and admin role
            Database.SetInitializer<Context>(new ApplicationDbInitializer());
        }

        public static Context Create()
        {
            return new Context();
        }
    }
}