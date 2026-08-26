using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using VerifierAPI.Service;
using System.Security.Claims;
using System.Text.RegularExpressions;
using VerifierAPI.Databases;
using VerifierAPI.Models;
using Microsoft.AspNetCore.Http;
using ILogger = NLog.ILogger;

public class AccountController : Controller
{
    private const string PendingReturnCookie = "thaiid_pending_return";
    protected ILogger log = NLog.LogManager.GetCurrentClassLogger();

    [HttpGet]
    [AllowAnonymous]
    public IActionResult Login(string? ReturnUrl)
    {
        ViewBag.ReturnUrl = ReturnUrl;
        return View();
    }

    [HttpPost]
    [AllowAnonymous]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Login(AuthenUser user, string? ReturnUrl)
    {
        if (!ModelState.IsValid)
        {
            return View(user);
        }

        using var context = new VerifierDbContext();
        var dbUser = context.Dbusers
            .FirstOrDefault(u => u.Username == user.username);

        if (dbUser == null || !VerifyPassword(user.password, dbUser.Password))
        {
            ModelState.AddModelError("ErrorMsg", "Invalid Username or Password");
            //log.Info($"Fail to log in as {user.username} (Session : {HttpContext.Session.Id})");
            return View(user);
        }

        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.Name, dbUser.Username),
            new Claim(ClaimTypes.NameIdentifier, dbUser.Id.ToString()),
        };
        var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        var authProperties = new AuthenticationProperties
        {
            IsPersistent = false,
            ExpiresUtc = DateTimeOffset.UtcNow.AddMinutes(60)
        };
        await HttpContext.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            new ClaimsPrincipal(claimsIdentity),
            authProperties);
        //log.Info($"Login success as {dbUser.Username}");

        if (!string.IsNullOrEmpty(ReturnUrl) && Url.IsLocalUrl(ReturnUrl))
        {
            return Redirect(ReturnUrl);
        }

        // เลือกอัตโนมัติจาก User-Agent ของเครื่องที่กำลัง login อยู่ ณ ตอนนี้
        // (เป็นการเดา ไม่แม่นยำ 100% แต่ user ไม่ต้องกดเลือกเอง - ตามที่คุยกันไว้)
        bool isMobile = Regex.IsMatch(
            Request.Headers.UserAgent.ToString(), "Android|iPhone|iPad|iPod",
            RegexOptions.IgnoreCase);

        return RedirectToAction("VerifyResult", "PresentResult");
    }

    [HttpPost]
    [Authorize]
    public async Task<IActionResult> Logout()
    {
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        return RedirectToAction("Login");
    }

    [AllowAnonymous]
    public IActionResult AccessDenied()
    {
        return View();
    }

    private bool VerifyPassword(string inputPassword, string storedPassword)
    {
        return inputPassword == storedPassword;
        // return BCrypt.Net.BCrypt.Verify(inputPassword, storedPassword);
    }

    [HttpGet]
    [AllowAnonymous]
    [Route("Account/ThaIDSignIn")]
    public async Task<IActionResult> ThaIDSignIn(string pid, string? ReturnUrl)
    {
        if (string.IsNullOrWhiteSpace(pid))
        {
            return RedirectToAction("Login", "Account", new { error = "ไม่พบข้อมูลยืนยันตัวตน" });
        }

        // sign-in cookie ให้ user ก่อน (แทนการเช็ค username/password เหมือนของเดิม
        // เพราะ pid ที่ได้มา ผ่านการยืนยันตัวตนจริงจาก ThaID แล้ว)
        var claims = new List<Claim>
    {
        new Claim(ClaimTypes.NameIdentifier, pid)
    };

        var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        var authProperties = new AuthenticationProperties
        {
            IsPersistent = false,
            ExpiresUtc = DateTimeOffset.UtcNow.AddMinutes(60)
        };

        await HttpContext.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            new ClaimsPrincipal(claimsIdentity),
            authProperties);

        // -------------------------------------------------------
        // logic เดียวกับ Login (username/password) เดิมของ Verifier
        // -------------------------------------------------------
        // FIX (2026-08-15): the ReturnUrl query param almost never actually
        // arrives here in the real flow — this action is the redirect_uri the
        // external ThaID gateway calls back to, and the gateway only appends
        // its own params (pid), not ours. That's exactly why ThaIDLogin
        // (/thaiid/login, below) stashes {ReturnUrl, DocumentType} in the
        // thaiid_pending_return cookie before leaving for the gateway — but
        // nothing ever read that cookie back until now, so every ThaID login
        // silently ignored where the user actually came from (e.g.
        // VerifyScanQR) and always landed on VerifyResult. Fall back to the
        // cookie when the query param is empty, then clear it either way.
        string? effectiveReturnUrl = ReturnUrl;
        if (string.IsNullOrEmpty(effectiveReturnUrl) &&
            Request.Cookies.TryGetValue(PendingReturnCookie, out var pendingJson) &&
            !string.IsNullOrEmpty(pendingJson))
        {
            try
            {
                var pending = JsonConvert.DeserializeObject<Newtonsoft.Json.Linq.JObject>(pendingJson);
                effectiveReturnUrl = pending?["ReturnUrl"]?.ToString();
            }
            catch (Exception ex)
            {
                log.Warn("ThaIDSignIn: failed to parse " + PendingReturnCookie + " cookie => " + ex.Message);
            }
        }
        Response.Cookies.Delete(PendingReturnCookie);

        if (!string.IsNullOrEmpty(effectiveReturnUrl) && Url.IsLocalUrl(effectiveReturnUrl))
        {
            return Redirect(effectiveReturnUrl);
        }

        // เลือกอัตโนมัติจาก User-Agent ของเครื่องที่กำลัง login อยู่ ณ ตอนนี้
        // (เป็นการเดา ไม่แม่นยำ 100% แต่ user ไม่ต้องกดเลือกเอง - ตามที่คุยกันไว้)
        bool isMobile = Regex.IsMatch(
            Request.Headers.UserAgent.ToString(), "Android|iPhone|iPad|iPod",
            RegexOptions.IgnoreCase);

        return RedirectToAction("VerifyResult", "PresentResult");
    }

    [HttpGet]
    [AllowAnonymous]
    public IActionResult ThaIDLogin(string? ReturnUrl, DocumentType? documentType)
    {
        ViewBag.ReturnUrl = ReturnUrl;
        ViewBag.DocumentType = documentType; // ต้องส่งต่อผ่าน hidden field ใน view เพื่อรอด POST กลับมา
        return View();
    }

    [HttpGet]
    [AllowAnonymous]
    [Route("thaiid/login")]
    public IActionResult ThaIDLogin(string? returnUrl, DocumentType? documentType, string? error = null)
    {
        try
        {
            string clientId = ThaIDConfig.ClientID;

            // Gateway (.155) endpoint ที่แสดงหน้า QR ให้ user สแกนด้วยแอป ThaID
            string authUrl = $"{ThaIDConfig.GatewayBaseUrl}/auth/index?clientid={clientId}&role=verifier&documentType={documentType}";

            // เก็บ returnUrl/documentType ไว้ใน cookie ชั่วคราว (HttpOnly, อายุสั้น)
            // เพราะ browser จะออกจากหน้า .205 ไปที่ .155 แล้ววนกลับมาที่ ThaiIDCallback
            // โดยไม่มีทางส่ง custom parameter ผ่าน .155/ThaID ไปกลับมาได้เอง
            var pending = new { ReturnUrl = returnUrl, DocumentType = documentType };
            Response.Cookies.Append(PendingReturnCookie, JsonConvert.SerializeObject(pending), new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Lax,
                Expires = DateTimeOffset.UtcNow.AddMinutes(10)
            });

            return Redirect(authUrl);
        }
        catch (Exception ex)
        {
            log.Error("ThaID.Login => " + ex.ToString());
            return RedirectToAction("ThaIDLogin", "Account",
                new { error = "ไม่สามารถเชื่อมต่อ ThaiID ได้" });
        }
    }
}