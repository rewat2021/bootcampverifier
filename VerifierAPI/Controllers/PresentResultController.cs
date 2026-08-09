using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using VerifierAPI.Databases;
using static QRCoder.PayloadGenerator;

namespace VerifierAPI.Controllers
{
    // SECURITY (H-08 remediation, 2026-08-09): these pages render verification
    // results (including raw VP/VC token material) for a given session ID with no
    // login requirement, so anyone who obtained or guessed a session ID could view
    // another person's verified identity data. All actions here are now restricted
    // to the operator/verifier's authenticated browser session (the same cookie
    // auth already used by AccountController). See OID4VP-1.0-COMPLIANCE-AUDIT.md
    // finding H-08.
    [Authorize]
    public class PresentResultController : Controller
    {
        public IActionResult Result(string id)
        {
            try
            {
                ViewBag.Result = null;
                VerifierDbContext context = new VerifierDbContext();
                var result = context.Dbverifierresponses.Where(i => i.SessionId == id).FirstOrDefault();
                if (result == null)
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

        public IActionResult BootCamp(string id)
        {
            try
            {
                ViewBag.Result = null;
                VerifierDbContext context = new VerifierDbContext();
                var result = context.Dbverifierresponses.Where(i => i.SessionId == id).FirstOrDefault();
                if (result == null)
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

        public IActionResult VerifyResult()
        {
            return View();


            //return Content(baseUrl);

        }

        [HttpGet("/VerifyScanQR")]
        public IActionResult VerifyScanQR()
        {
            return View();
        }
    }
}
