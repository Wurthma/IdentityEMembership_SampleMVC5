using System;
using System.Data.Entity;
using System.Threading.Tasks;
using System.Net;
using System.Web.Mvc;
using CodingCraftMod1Ex4Auth.Models;

namespace CodingCraftMod1Ex4Auth.Controllers
{
    [Authorize(Roles = "Admin")]
    public class MembershipsController : Controller
    {
        private CodingCraftMod1Ex4AuthMembershipContext db = new CodingCraftMod1Ex4AuthMembershipContext();

        // GET: Memberships
        public async Task<ActionResult> Index()
        {
            var memberships = db.Memberships.Include(m => m.CustomUser);
            return View(await memberships.ToListAsync());
        }

        // GET: Memberships/Details/5
        public async Task<ActionResult> Details(Guid? id)
        {
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            Membership membership = await db.Memberships.FindAsync(id);
            if (membership == null)
            {
                return HttpNotFound();
            }
            return View(membership);
        }

        // GET: Memberships/Create
        public ActionResult Create()
        {
            ViewBag.CustomUserId = new SelectList(db.CustomUsers, "CustomUserId", "Name");
            return View();
        }

        // POST: Memberships/Create
        // To protect from overposting attacks, please enable the specific properties you want to bind to, for 
        // more details see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Create([Bind(Include = "MembershipId,CustomUserId,ConfirmationToken,IsConfirmed,LastPasswordFailureDate,PasswordFailuresSinceLastSuccess,Password,PasswordChangedDate,PasswordVerificationToken,PasswordVerificationTokenExpirationDate,LastModified,CreatedOn")] Membership membership)
        {
            if (ModelState.IsValid)
            {
                membership.MembershipId = Guid.NewGuid();
                db.Memberships.Add(membership);
                await db.SaveChangesAsync();
                return RedirectToAction("Index");
            }

            ViewBag.CustomUserId = new SelectList(db.CustomUsers, "CustomUserId", "Name", membership.CustomUserId);
            return View(membership);
        }

        // GET: Memberships/Edit/5
        public async Task<ActionResult> Edit(Guid? id)
        {
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            Membership membership = await db.Memberships.FindAsync(id);
            if (membership == null)
            {
                return HttpNotFound();
            }
            ViewBag.CustomUserId = new SelectList(db.CustomUsers, "CustomUserId", "Name", membership.CustomUserId);
            return View(membership);
        }

        // POST: Memberships/Edit/5
        // To protect from overposting attacks, please enable the specific properties you want to bind to, for 
        // more details see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Edit([Bind(Include = "MembershipId,CustomUserId,ConfirmationToken,IsConfirmed,LastPasswordFailureDate,PasswordFailuresSinceLastSuccess,Password,PasswordChangedDate,PasswordVerificationToken,PasswordVerificationTokenExpirationDate,LastModified,CreatedOn")] Membership membership)
        {
            if (ModelState.IsValid)
            {
                db.Entry(membership).State = EntityState.Modified;
                await db.SaveChangesAsync();
                return RedirectToAction("Index");
            }
            ViewBag.CustomUserId = new SelectList(db.CustomUsers, "CustomUserId", "Name", membership.CustomUserId);
            return View(membership);
        }

        // GET: Memberships/Delete/5
        public async Task<ActionResult> Delete(Guid? id)
        {
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            Membership membership = await db.Memberships.FindAsync(id);
            if (membership == null)
            {
                return HttpNotFound();
            }
            return View(membership);
        }

        // POST: Memberships/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> DeleteConfirmed(Guid id)
        {
            Membership membership = await db.Memberships.FindAsync(id);
            db.Memberships.Remove(membership);
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
