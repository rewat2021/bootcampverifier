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
using System.Web;
using ILogger = NLog.ILogger;

public class AccountController : Controller
{
    private const string PendingReturnCookie = "thaiid_pending_return";
    protected ILogger log = NLog.LogManager.GetCurrentClassLogger();
    private readonly ThaIDService _thaIdService;

    public AccountController(ThaIDService thaIdService)
    {
        _thaIdService = thaIdService;
    }

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

    // SECURITY (2026-08-27): DISABLED. This endpoint used to sign a user in from
    // a bare `pid` query-string value with zero proof it actually came from
    // ThaID — anyone could hit /Account/ThaIDSignIn?pid=<any citizen id> directly
    // in a browser and be signed in as that person, no ThaID app interaction
    // required at all. Real ThaID sign-in now goes through /thaiid/login ->
    // DOPA ThaID -> /api/thaid/callback (state-verified, server-to-server code
    // exchange — see ThaiIDCallback / ThaIDService.cs). Left as a stub that
    // always 410s, same pattern as VerifierController.GetVP's disabled endpoint,
    // rather than removed outright, so any stale bookmark/link gets a clear
    // "gone" instead of a silent 404.
    [HttpGet]
    [AllowAnonymous]
    [Route("Account/ThaIDSignIn")]
    public IActionResult ThaIDSignIn(string pid, string? ReturnUrl)
    {
        return StatusCode(410, new
        {
            error = "endpoint_disabled",
            error_description = "This endpoint has been disabled — it trusted an unverified pid value. Sign in via /thaiid/login instead."
        });
    }

    // NOTE: keeps a 2-parameter signature (ReturnUrl, documentType) — the
    // overload below (`[Route("thaiid/login")]`) already declares a 3rd `error`
    // parameter, and C# doesn't allow two methods in the same class with
    // identical parameter-type lists no matter what routing attributes say. This
    // one reads `error` straight off the query string instead of as a formal
    // parameter, so both actions can still show it without a signature clash.
    [HttpGet]
    [AllowAnonymous]
    public IActionResult ThaIDLogin(string? ReturnUrl, DocumentType? documentType)
    {
        ViewBag.ReturnUrl = ReturnUrl;
        ViewBag.DocumentType = documentType; // ต้องส่งต่อผ่าน hidden field ใน view เพื่อรอด POST กลับมา
        ViewBag.Error = Request.Query["error"].ToString();
        return View();
    }

    [HttpGet]
    [AllowAnonymous]
    [Route("thaiid/login")]
    public IActionResult ThaIDLogin(string? ReturnUrl, DocumentType? documentType, string? error = null)
    {
        //try
        //{
        //    string clientId = ThaIDConfig.ClientID;

        //    // Gateway (.155) endpoint ที่แสดงหน้า QR ให้ user สแกนด้วยแอป ThaID
        //    string authUrl = $"{ThaIDConfig.GatewayBaseUrl}/auth/index?clientid={clientId}&role=verifier&documentType={documentType}";

        //    // เก็บ returnUrl/documentType ไว้ใน cookie ชั่วคราว (HttpOnly, อายุสั้น)
        //    // เพราะ browser จะออกจากหน้า .205 ไปที่ .155 แล้ววนกลับมาที่ ThaiIDCallback
        //    // โดยไม่มีทางส่ง custom parameter ผ่าน .155/ThaID ไปกลับมาได้เอง
        //    var pending = new { ReturnUrl = returnUrl, DocumentType = documentType };
        //    Response.Cookies.Append(PendingReturnCookie, JsonConvert.SerializeObject(pending), new CookieOptions
        //    {
        //        HttpOnly = true,
        //        Secure = true,
        //        SameSite = SameSiteMode.Lax,
        //        Expires = DateTimeOffset.UtcNow.AddMinutes(10)
        //    });

        //    return Redirect(authUrl);
        //}
        //catch (Exception ex)
        //{
        //    log.Error("ThaID.Login => " + ex.ToString());
        //    return RedirectToAction("ThaIDLogin", "Account",
        //        new { error = "ไม่สามารถเชื่อมต่อ ThaiID ได้" });
        //}

        try
        {
            //string clientId = ThaIDConfig.ClientID;

            // Gateway (.155) endpoint ที่แสดงหน้า QR ให้ user สแกนด้วยแอป ThaID
            //string authUrl = $"{ThaIDConfig.GatewayBaseUrl}/auth/index?clientid={clientId}&role=Issuer&ReturnUrl={ReturnUrl}&documentType={documentType}";

            // เก็บ returnUrl/documentType ไว้ใน cookie ชั่วคราว (HttpOnly, อายุสั้น) เพราะ browser จะออกจาก
            // หน้านี้ไปที่ ThaID แล้ววนกลับมาที่ ThaiIDCallback โดยไม่มีทางส่ง custom parameter ผ่าน ThaID ไป-
            // กลับมาได้เอง (ThaID ส่งกลับมาแค่ code/state ที่มันควบคุมเอง)
            //
            // บั๊กที่แก้: บล็อกนี้เคย comment ทิ้งไว้ทั้งก้อน — แปลว่า ReturnUrl/documentType ที่รับเข้ามาถูก
            // ทิ้งไปเฉยๆ ไม่เคยถูกเก็บที่ไหนเลย ผลคือ ThaiIDCallback อ่าน cookie ไม่เจอทุกครั้ง (pendingReturnUrl
            // เป็น null เสมอ) จึง fall through ไปทาง fallback (/QR/QRCode) ตลอด ไม่ว่าจะ login มาจาก flow
            // same-device (wallet เปิด browser มาขอ redirect ตรง) หรือไม่ก็ตาม — same-device เลยเห็น QR
            // page เหมือน cross-device ทุกครั้ง ทั้งที่ควรจะ redirect ตรงไป wallet เลยโดยไม่ต้อง scan
            // SECURITY (2026-08-27): state is now ALWAYS generated and stashed here —
            // previously the pending cookie (and the state value itself) was only
            // written when ReturnUrl/documentType were present, so most logins had
            // nothing to check state against at all. ThaiIDCallback below verifies
            // this exact state comes back before trusting anything else in the
            // callback — see that method for why.
            string state = Guid.NewGuid().ToString("N");
            var pending = new { ReturnUrl = ReturnUrl, DocumentType = documentType, State = state };
            Response.Cookies.Append(PendingReturnCookie, JsonConvert.SerializeObject(pending), new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Lax,
                Expires = DateTimeOffset.UtcNow.AddMinutes(10)
            });

            string clientId = ThaIDConfig.ClientID;
            string clientSecret = ThaIDConfig.ClientSecret;
            string redirectUri = $"{Request.Scheme}://{Request.Host}" + ThaIDConfig.RedirectURL;
            string scope = "";// ThaIDConfig.Scope;
            string GatewayBaseUrl = ThaIDConfig.GatewayBaseUrl + "/api/v2/oauth2/auth/?";

            log.Info($"redirect_uri => {redirectUri}");
            scope = "pid%20given_name%20family_name%20given_name_en%20family_name_en%20gender%20title%20title_en%20date_of_issuance%20date_of_expiry%20address%20birthdate";
            string authUrl = GatewayBaseUrl +
                               "response_type=code" +
                               "&client_id=" + clientId +
                               "&redirect_uri=" + HttpUtility.UrlEncode(redirectUri) +
                               "&scope=" + scope + "%20openid" +
                               "&state=" + state;
            //HttpUtility.UrlEncode(scope) 
            return Redirect(authUrl);


        }
        catch (Exception ex)
        {
            log.Error("ThaID.Login => " + ex.ToString());
            return RedirectToAction("ThaIDLogin", "Account",
                new { error = "ไม่สามารถเชื่อมต่อ ThaiID ได้" });
        }


    }

    // SECURITY (2026-08-27): this used to be a stub (`return Json("")`) — the
    // endpoint that was ACTUALLY signing users in was ThaIDSignIn above, which
    // took a bare `pid` query-string value with zero proof it came from ThaID at
    // all (anyone could hit /Account/ThaIDSignIn?pid=<any citizen id> directly
    // and be signed in as that person). This is the real DOPA ThaID OAuth2
    // callback: it verifies `state` against what /thaiid/login stashed, then
    // exchanges the authorization `code` for an id_token server-to-server (using
    // ThaIDConfig's client_id/client_secret — see ThaIDService), and only trusts
    // the citizen id that comes back from THAT verified exchange.
    [HttpGet]
    [AllowAnonymous]
    [Route("api/thaid/callback")]
    public async Task<IActionResult> ThaiIDCallback(string code, string state, string error = null)
    {
        try
        {
            // 1) ตรวจ error จาก provider
            if (!string.IsNullOrWhiteSpace(error))
            {
                return RedirectToAccountLogin("ThaID ส่งค่ากลับมาผิดพลาด: " + error);
            }

            // 2) ตรวจ code
            if (string.IsNullOrWhiteSpace(code))
            {
                return StatusCode(400, "Authorization code not found");
            }

            // 3) ตรวจ state ต้องมีค่า และต้องตรงกับค่าที่ /thaiid/login เก็บไว้ก่อนออกไป DOPA
            //    (ป้องกัน CSRF — ไม่มีขั้นตอนนี้ ใครก็ปลอม request มาที่ endpoint นี้ได้)
            if (string.IsNullOrWhiteSpace(state))
            {
                return RedirectToAccountLogin("ไม่พบ state จาก ThaiID");
            }

            string? pendingReturnUrl = null;
            DocumentType? pendingDocumentType = null;
            string? pendingState = null;
            if (Request.Cookies.TryGetValue(PendingReturnCookie, out var pendingJson) &&
                !string.IsNullOrWhiteSpace(pendingJson))
            {
                var pending = JsonConvert.DeserializeAnonymousType(pendingJson,
                    new { ReturnUrl = (string?)null, DocumentType = (DocumentType?)null, State = (string?)null });
                pendingReturnUrl = pending?.ReturnUrl;
                pendingDocumentType = pending?.DocumentType;
                pendingState = pending?.State;
            }
            // ลบ cookie ทันทีไม่ว่าผลตรวจจะผ่านหรือไม่ — ใช้ครั้งเดียว (กัน replay ของ pending cookie เอง)
            Response.Cookies.Delete(PendingReturnCookie);

            if (string.IsNullOrWhiteSpace(pendingState) ||
                !string.Equals(pendingState, state, StringComparison.Ordinal))
            {
                log.Warn($"ThaiIDCallback: state mismatch (got '{state}', expected '{pendingState ?? "<none>"}')");
                return RedirectToAccountLogin("การเข้าสู่ระบบไม่ถูกต้อง (state ไม่ตรงกัน) กรุณาลองใหม่อีกครั้ง");
            }

            // 4) แลก code -> token กับ DOPA ThaID โดยตรง (endpoint เดียวกับที่ ThaIDLogin ยิงไป authorize)
            //    redirectUri ต้องเหมือนกับที่ส่งไปตอน authorize เป๊ะๆ (ข้อกำหนดของ OAuth2)
            string redirectUri = $"{Request.Scheme}://{Request.Host}" + "/api/thaid/callback";
            var token = await _thaIdService.GetAccessTokenAsync(code, redirectUri);
            if (token == null || string.IsNullOrWhiteSpace(token.IDToken))
            {
                log.Error("ThaiIDCallback: GetAccessTokenAsync failed or id_token missing");
                return RedirectToAccountLogin("ไม่สามารถขอ token จาก ThaiID ได้");
            }

            // 5) ดึง PID + ข้อมูลส่วนตัวจาก claims ใน id_token โดยตรง — ไม่ต้องเรียก endpoint แยกอีกรอบ
            string citizenId = _thaIdService.GetCitizenId(token);
            if (string.IsNullOrWhiteSpace(citizenId))
            {
                log.Error("ThaiIDCallback: GetCitizenId failed or pid/sub missing from id_token => state=" + state);
                return RedirectToAccountLogin("ไม่สามารถยืนยันตัวตนผ่าน ThaID ได้ (ไม่พบ PID ใน id_token)");
            }
            var profile = _thaIdService.GetProfile(token);
            log.Info("ThaiIDCallback: id_token PID => " + citizenId);

            // 6) สร้าง claims จาก PID ที่ตรวจสอบแล้ว แล้ว sign-in cookie ให้ user
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, citizenId),
            };
            var fullNameTh = $"{profile?.FirstNameTh} {profile?.LastNameTh}".Trim();
            if (!string.IsNullOrWhiteSpace(fullNameTh))
            {
                claims.Add(new Claim(ClaimTypes.Name, fullNameTh));
            }
            if (!string.IsNullOrWhiteSpace(profile?.TitleNameTh))
                claims.Add(new Claim("thaid_title", profile.TitleNameTh));
            if (!string.IsNullOrWhiteSpace(profile?.BirthDate))
                claims.Add(new Claim(ClaimTypes.DateOfBirth, profile.BirthDate));
            if (!string.IsNullOrWhiteSpace(profile?.Gender))
                claims.Add(new Claim(ClaimTypes.Gender, profile.Gender));

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

            // 7) ตัดสินใจ redirect ปลายทาง — เหมือน logic เดิมของ ThaIDSignIn
            if (!string.IsNullOrEmpty(pendingReturnUrl) && Url.IsLocalUrl(pendingReturnUrl))
            {
                return Redirect(pendingReturnUrl);
            }

            return RedirectToAction("VerifyResult", "PresentResult");
        }
        catch (Exception ex)
        {
            log.Error(ex, "ThaiIDCallback => " + ex.Message);
            return RedirectToAccountLogin("เกิดข้อผิดพลาดระหว่างเข้าสู่ระบบด้วย ThaID");
        }
    }

    private IActionResult RedirectToAccountLogin(string error)
    {
        return RedirectToAction("ThaIDLogin", "Account", new { error });
    }
}