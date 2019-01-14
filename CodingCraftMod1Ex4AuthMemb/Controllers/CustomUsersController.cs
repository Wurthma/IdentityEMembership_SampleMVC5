using System;
using System.Data.Entity;
using System.Threading.Tasks;
using System.Net;
using System.Web.Mvc;
using CodingCraftMod1Ex4Auth.Models;

namespace CodingCraftMod1Ex4Auth.Controllers
{
    [Authorize(Roles = "Admin")]
    public class CustomUsersController : Controller
    {
        private CodingCraftMod1Ex4AuthMembershipContext db = new CodingCraftMod1Ex4AuthMembershipContext();

        // GET: CustomUsers
        public async Task<ActionResult> Index()
        {
            return View(await db.CustomUsers.ToListAsync());
        }

        // GET: CustomUsers/Details/5
        public async Task<ActionResult> Details(Guid? id)
        {
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            CustomUser customUser = await db.CustomUsers.FindAsync(id);
            if (customUser == null)
            {
                return HttpNotFound();
            }
            return View(customUser);
        }

        // GET: CustomUsers/Create
        public ActionResult Create()
        {
            return View();
        }

        // POST: CustomUsers/Create
        // To protect from overposting attacks, please enable the specific properties you want to bind to, for 
        // more details see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Create([Bind(Include = "CustomUserId,Name,FirstName,LastName,Suspended,LastModified,CreatedOn")] CustomUser customUser)
        {
            if (ModelState.IsValid)
            {
                customUser.CustomUserId = Guid.NewGuid();
                db.CustomUsers.Add(customUser);
                await db.SaveChangesAsync();
                return RedirectToAction("Index");
            }

            return View(customUser);
        }

        // GET: CustomUsers/Edit/5
        public async Task<ActionResult> Edit(Guid? id)
        {
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            CustomUser customUser = await db.CustomUsers.FindAsync(id);
            if (customUser == null)
            {
                return HttpNotFound();
            }
            return View(customUser);
        }

        // POST: CustomUsers/Edit/5
        // To protect from overposting attacks, please enable the specific properties you want to bind to, for 
        // more details see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Edit([Bind(Include = "CustomUserId,Name,FirstName,LastName,Suspended,LastModified,CreatedOn")] CustomUser customUser)
        {
            if (ModelState.IsValid)
            {
                db.Entry(customUser).State = EntityState.Modified;
                await db.SaveChangesAsync();
                return RedirectToAction("Index");
            }
            return View(customUser);
        }

        // GET: CustomUsers/Delete/5
        public async Task<ActionResult> Delete(Guid? id)
        {
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            CustomUser customUser = await db.CustomUsers.FindAsync(id);
            if (customUser == null)
            {
                return HttpNotFound();
            }
            return View(customUser);
        }

        // POST: CustomUsers/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> DeleteConfirmed(Guid id)
        {
            CustomUser customUser = await db.CustomUsers.FindAsync(id);
            db.CustomUsers.Remove(customUser);
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
