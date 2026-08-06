using Microsoft.AspNetCore.Mvc;
using VerifierAPI.Databases;
using static QRCoder.PayloadGenerator;

namespace VerifierAPI.Controllers
{
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
