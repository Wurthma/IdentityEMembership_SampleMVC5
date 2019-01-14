using System;
using System.Data.Entity;
using System.Threading.Tasks;
using System.Net;
using System.Web.Mvc;
using CodingCraftMod1Ex4Auth.Models;

namespace CodingCraftMod1Ex4Auth.Controllers
{
    [Authorize(Roles = "Admin")]
    public class UserRolesController : Controller
    {
        private CodingCraftMod1Ex4AuthMembershipContext db = new CodingCraftMod1Ex4AuthMembershipContext();

        // GET: UserRoles
        public async Task<ActionResult> Index()
        {
            var userRoles = db.UserRoles.Include(u => u.CustomUser).Include(u => u.Role);
            return View(await userRoles.ToListAsync());
        }

        // GET: UserRoles/Details/5
        public async Task<ActionResult> Details(Guid? id)
        {
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            UserRole userRole = await db.UserRoles.FindAsync(id);
            if (userRole == null)
            {
                return HttpNotFound();
            }
            return View(userRole);
        }

        // GET: UserRoles/Create
        public ActionResult Create()
        {
            ViewBag.CustomUserId = new SelectList(db.CustomUsers, "CustomUserId", "Name");
            ViewBag.RoleId = new SelectList(db.Roles, "RoleId", "Name");
            return View();
        }

        // POST: UserRoles/Create
        // To protect from overposting attacks, please enable the specific properties you want to bind to, for 
        // more details see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Create([Bind(Include = "UserRoleId,CustomUserId,RoleId,LastModified,CreatedOn")] UserRole userRole)
        {
            if (ModelState.IsValid)
            {
                userRole.UserRoleId = Guid.NewGuid();
                db.UserRoles.Add(userRole);
                await db.SaveChangesAsync();
                return RedirectToAction("Index");
            }

            ViewBag.CustomUserId = new SelectList(db.CustomUsers, "CustomUserId", "Name", userRole.CustomUserId);
            ViewBag.RoleId = new SelectList(db.Roles, "RoleId", "Name", userRole.RoleId);
            return View(userRole);
        }

        // GET: UserRoles/Edit/5
        public async Task<ActionResult> Edit(Guid? id)
        {
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            UserRole userRole = await db.UserRoles.FindAsync(id);
            if (userRole == null)
            {
                return HttpNotFound();
            }
            ViewBag.CustomUserId = new SelectList(db.CustomUsers, "CustomUserId", "Name", userRole.CustomUserId);
            ViewBag.RoleId = new SelectList(db.Roles, "RoleId", "Name", userRole.RoleId);
            return View(userRole);
        }

        // POST: UserRoles/Edit/5
        // To protect from overposting attacks, please enable the specific properties you want to bind to, for 
        // more details see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Edit([Bind(Include = "UserRoleId,CustomUserId,RoleId,LastModified,CreatedOn")] UserRole userRole)
        {
            if (ModelState.IsValid)
            {
                db.Entry(userRole).State = EntityState.Modified;
                await db.SaveChangesAsync();
                return RedirectToAction("Index");
            }
            ViewBag.CustomUserId = new SelectList(db.CustomUsers, "CustomUserId", "Name", userRole.CustomUserId);
            ViewBag.RoleId = new SelectList(db.Roles, "RoleId", "Name", userRole.RoleId);
            return View(userRole);
        }

        // GET: UserRoles/Delete/5
        public async Task<ActionResult> Delete(Guid? id)
        {
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            UserRole userRole = await db.UserRoles.FindAsync(id);
            if (userRole == null)
            {
                return HttpNotFound();
            }
            return View(userRole);
        }

        // POST: UserRoles/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> DeleteConfirmed(Guid id)
        {
            UserRole userRole = await db.UserRoles.FindAsync(id);
            db.UserRoles.Remove(userRole);
            await db.SaveChangesAsync();
            return RedirectToAction("Index");
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                db.Dispose();
            }
            base.Dispose(disposing);
        }
    }
}
