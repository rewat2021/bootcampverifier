using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using VerifierAPI.Databases;
using static QRCoder.PayloadGenerator;

namespace VerifierAPI.Controllers
{
    // SECURITY (H-08 remediation, 2026-08-09): these pages render verification
    // results (including raw VP/VC token material) for a given session ID.
    // FIX (H-08 follow-up, 2026-08-15): [Authorize] was originally applied to
    // the whole controller, including Result/BootCamp. But those two actions
    // ARE the OpenID4VP redirect_uri target — reached directly by the Holder's
    // own Wallet browser/webview right after it POSTs the vp_token, per
    // VerifierController.VerifierVP. That browser never goes through this app's
    // ThaID cookie login (that's a separate, unrelated operator/self-service
    // flow — see AccountController/VerifyResult/VerifyScanQR), so [Authorize]
    // here just bounced every real presentation redirect to the ThaID login
    // page instead of showing the result — reported as "redirect มาแล้วหน้า
    // error". Confirmed with the user: this page is meant to be viewable by
    // the Holder right after they scan the Verifier's QR, not gated behind an
    // operator session. The M-02 fix (below) is what actually protects this
    // URL — a freshly generated, single-use, 30-minute-lived ResponseCode that
    // an attacker cannot guess — so Result/BootCamp are now [AllowAnonymous]
    // and only VerifyResult/VerifyScanQR (the separate ThaID-authenticated
    // self-service flow) keep [Authorize]. See OID4VP-1.0-COMPLIANCE-AUDIT.md
    // findings H-08, M-02.
    public class PresentResultController : Controller
    {
        // FIX (M-02, 2026-08-09): the redirect_uri path segment is now a freshly
        // generated, single-response ResponseCode (see VerifierController.VerifierVP)
        // instead of the session id — so lookups here are by ResponseCode, with a
        // short validity window from when the response was received, instead of
        // being indefinitely reachable by session id.
        // See OID4VP-1.0-COMPLIANCE-AUDIT.md finding M-02.
        private static readonly TimeSpan ResponseCodeValidity = TimeSpan.FromMinutes(30);

        [AllowAnonymous]
        public IActionResult Result(string id)
        {
            try
            {
                ViewBag.Result = null;
                VerifierDbContext context = new VerifierDbContext();
                var result = context.Dbverifierresponses.Where(i => i.ResponseCode == id).FirstOrDefault();
                if (result == null || result.ReceivedAt.Add(ResponseCodeValidity) < DateTime.UtcNow)
                {
                    ViewBag.Result = "ไม่พบรายการข้อมูล";
                    return View();
                }

                ViewBag.VPToken = result.VpToken;
                ViewBag.VCToken = result.VcPayload;


                return View(result);
            }
            catch (Exception e)
            {
                ViewBag.Result = "ไม่พบรายการข้อมูล";
                return View(new Dbverifierresponse()); // ← เพิ่มตรงนี้
            }


            //return Content(baseUrl);

        }

        [Authorize]
        public IActionResult VerifyResult()
        {
            return View();


            //return Content(baseUrl);

        }

        [Authorize]
        [HttpGet("/VerifyScanQR")]
        public IActionResult VerifyScanQR()
        {
            return View();
        }
    }
}
