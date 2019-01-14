using System.Web;
using System.Web.Mvc;

namespace CodingCraftMod1Ex4Auth
{
    public class FilterConfig
    {
        public static void RegisterGlobalFilters(GlobalFilterCollection filters)
        {
            filters.Add(new HandleErrorAttribute());
        }
    }
}
