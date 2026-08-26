using System;
using System.Linq;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using VerifierAPI.Databases;

namespace VerifierAPI.Controllers
{
    // FEATURE (audit trail, 2026-08-15): frontend page for staff to review the
    // verification audit log — VerifierAuditLogFilter writes a row to
    // dbverifierlog on every VerifierVP call (success AND every failure
    // branch: bad signature, DCQL mismatch, replay, mdoc verify failed,
    // expired/unknown/already-consumed session, Wallet-declined, etc.).
    // [Authorize] — same ThaID-backed cookie auth as VerifyScanQR/VerifyResult
    // (see AccountController / Program.cs) — this page shows verification
    // outcomes, error reasons, and requester IP/User-Agent, which should not
    // be publicly viewable. See OID4VP-1.0-COMPLIANCE-AUDIT.md.
    [Authorize]
    public class AuditLogController : Controller
    {
        private const int PageSize = 50;

        [HttpGet("/AuditLog")]
        public IActionResult Index(int page = 1, string? status = null)
        {
            if (page < 1) page = 1;

            using var context = new VerifierDbContext();
            var query = context.Dbverifierlogs.AsQueryable();
            string? normalizedStatus = null;
            if (string.Equals(status, "success", StringComparison.OrdinalIgnoreCase))
                normalizedStatus = "success";
            else if (string.Equals(status, "failed", StringComparison.OrdinalIgnoreCase))
                normalizedStatus = "failed";

            if (normalizedStatus != null)
            {
                query = query.Where(l => l.Status == normalizedStatus);
            }

            int totalCount = query.Count();
            int totalPages = Math.Max(1, (int)Math.Ceiling(totalCount / (double)PageSize));
            if (page > totalPages) page = totalPages;

            var entries = query
                .OrderByDescending(l => l.CreatedAt)
                .Skip((page - 1) * PageSize)
                .Take(PageSize)
                .ToList();

            ViewBag.Page = page;
            ViewBag.TotalPages = totalPages;
            ViewBag.TotalCount = totalCount;
            ViewBag.StatusFilter = normalizedStatus;

            return View(entries);
        }
    }
}
