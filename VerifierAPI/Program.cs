using Microsoft.AspNetCore.Authentication.Cookies;
using NLog;
using NLog.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using VerifierAPI.Service;

// SECURITY (C-05 remediation, 2026-08-26): ThaIDConfig__ClientID / __ClientSecret /
// CONNECTION_STRING now come from environment variables only — appsettings.json no
// longer carries a real value (see appsettings.json). Docker gets these from
// `env_file: .env` in docker-compose.yml already, at the container level, before
// this process even starts. Running from Visual Studio / `dotnet run` (no Docker)
// has no such mechanism, so this loads the SAME repo-root .env file directly into
// this process's environment variables — one secrets file for both paths, instead
// of keeping a separate copy in User Secrets. Never overrides a variable that's
// already set (so a real Docker/hosting environment always wins over this file),
// and does nothing at all if no .env is found (e.g. inside the published
// container image, which never has one).
LoadDotEnvIfPresent();

static void LoadDotEnvIfPresent()
{
    var dir = new DirectoryInfo(AppContext.BaseDirectory);
    for (int i = 0; i < 8 && dir != null; i++, dir = dir.Parent)
    {
        var candidate = Path.Combine(dir.FullName, ".env");
        if (!File.Exists(candidate)) continue;

        foreach (var rawLine in File.ReadAllLines(candidate))
        {
            var line = rawLine.Trim();
            if (line.Length == 0 || line.StartsWith("#")) continue;

            var separatorIndex = line.IndexOf('=');
            if (separatorIndex <= 0) continue;

            var key = line.Substring(0, separatorIndex).Trim();
            var value = line.Substring(separatorIndex + 1).Trim();
            if (value.Length >= 2 &&
                ((value[0] == '"' && value[^1] == '"') || (value[0] == '\'' && value[^1] == '\'')))
            {
                value = value.Substring(1, value.Length - 2);
            }

            // Don't clobber a value the real environment already provided.
            if (Environment.GetEnvironmentVariable(key) == null)
                Environment.SetEnvironmentVariable(key, value);
        }
        break;
    }
}

var logger = LogManager.Setup()
                       .LoadConfigurationFromFile("nlog.config")
                       .GetCurrentClassLogger();

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

ThaIDConfig.Configure(builder.Configuration);
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/Account/ThaIDLogin";
        options.LogoutPath = "/Account/Logout";
        options.AccessDeniedPath = "/Account/AccessDenied";
        options.ExpireTimeSpan = TimeSpan.FromMinutes(60);
        options.SlidingExpiration = true;
        options.Cookie.HttpOnly = true;
        options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest; // ใช้ Always ถ้าบังคับ HTTPS

        // SECURITY (H-08 remediation, 2026-08-09): VerifierScanController is now
        // [Authorize]-protected but is called via fetch()/JS polling from
        // VerifyScanQR.cshtml, not by a full-page navigation. Without this, an
        // unauthenticated call would get a 302 redirect to the login page HTML
        // instead of a clean 401, which the polling JS can't act on sensibly.
        options.Events.OnRedirectToLogin = context =>
        {
            if (context.Request.Path.StartsWithSegments("/verifier"))
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                return Task.CompletedTask;
            }
            // NOTE (2026-08-15): VerifyScanQR (the operator's scanning terminal)
            // stays on this same ThaID LoginPath as every other [Authorize] page
            // — per the user's decision, it should require ThaID login too, not
            // a separate staff login. What makes this work correctly is that
            // AccountController.ThaIDSignIn now honors the ReturnUrl carried
            // through the ThaID round trip (via the thaiid_pending_return
            // cookie set in ThaIDLogin) instead of always landing on
            // VerifyResult — see AccountController.cs.
            context.Response.Redirect(context.RedirectUri);
            return Task.CompletedTask;
        };
    });

builder.Services.AddControllersWithViews()
    .AddJsonOptions(opts =>
    {
        opts.JsonSerializerOptions.Converters.Add(new JsonStringEnumConverter());
        opts.JsonSerializerOptions.PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower;
        opts.JsonSerializerOptions.DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull;
    });

var AllowSpecificOriginWithCredentials = "AllowSpecificOriginWithCredentials";
builder.Services.AddCors(options =>
{
    options.AddPolicy(AllowSpecificOriginWithCredentials,
                policy =>
                {
                    policy.SetIsOriginAllowed(origin =>
                    {
                        if (string.IsNullOrEmpty(origin))
                            return false;

                        try
                        {
                            var host = new Uri(origin).Host;
                            return host.Equals("etda.or.th", StringComparison.OrdinalIgnoreCase)
                                || host.EndsWith(".etda.or.th", StringComparison.OrdinalIgnoreCase)
                                || host.Equals("zenithcomp.co.th", StringComparison.OrdinalIgnoreCase)
                                || host.EndsWith(".zenithcomp.co.th", StringComparison.OrdinalIgnoreCase);
                        }
                        catch
                        {
                            return false;
                        }
                    })
                           .AllowAnyHeader()
                           .AllowAnyMethod()
                           .AllowCredentials(); // เปิดใช้ credentials (cookie, Authorization header ที่ต้องส่งข้าม origin)
                });

});

// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.UseInlineDefinitionsForEnums();
});

builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession();
// Clear default logging
builder.Logging.ClearProviders();

// Add NLog
builder.Host.UseNLog();


// HttpClient สำหรับยิงไปที่ Broker
// FIX (H-10, 2026-08-09): a short timeout so a slow/hanging broker can't tie up a
// request indefinitely, and AllowAutoRedirect = false so a broker response
// redirecting elsewhere can't silently escape the allowlist check already
// performed on the originally scanned URL (see VerifierRequestService.cs).
// See OID4VP-1.0-COMPLIANCE-AUDIT.md finding H-10.
builder.Services.AddHttpClient<VerifierAPI.Services.VerifierRequestService>(client =>
{
    client.Timeout = TimeSpan.FromSeconds(10);
})
.ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler
{
    AllowAutoRedirect = false
});

// Register service หลัก
builder.Services.AddScoped<VerifierAPI.Services.VerifierRequestService>();

// SECURITY (2026-08-27): HttpClient for ThaIDService's server-to-server call to
// the DOPA ThaID token endpoint (AccountController.ThaiIDCallback). See
// ThaIDService.cs for what this replaces (the old ThaIDSignIn endpoint trusted
// a bare `pid` query-string value with no verification at all).
builder.Services.AddHttpClient<ThaIDService>(client =>
{
    client.Timeout = TimeSpan.FromSeconds(15);
});


var app = builder.Build();

// FIX (2026-08-15): there was no global exception handling middleware at all —
// an unhandled exception anywhere past this point (including during Razor VIEW
// RENDERING, which happens after a controller action returns and is NOT caught
// by a controller-level try/catch) had nothing to turn it into an HTTP
// response. Depending on hosting (this app is published for in-process IIS
// hosting per web.config), that can surface to the browser as a raw connection
// reset / "This page can't be found" instead of any error page — reported for
// /PresentResult/Result/{id} even after the [Authorize] redirect issue (see
// PresentResultController) was already fixed, with the domain root and other
// routes confirmed reachable. This won't by itself explain what's throwing,
// but it turns any future "connection just dies" symptom into an actual
// logged, diagnosable 500 response instead of a silent reset — check
// logs/{date}.log (nlog.config) for the real exception after this deploys.
app.UseExceptionHandler(errApp =>
{
    errApp.Run(async context =>
    {
        var feature = context.Features.Get<Microsoft.AspNetCore.Diagnostics.IExceptionHandlerFeature>();
        logger.Error(feature?.Error, "Unhandled exception at {Path}", context.Request.Path);
        context.Response.StatusCode = StatusCodes.Status500InternalServerError;
        context.Response.ContentType = "text/html; charset=utf-8";
        await context.Response.WriteAsync(
            "<html><body style=\"font-family:sans-serif;padding:2rem\">" +
            "<h2>เกิดข้อผิดพลาดที่ไม่คาดคิด</h2>" +
            "<p>ระบบไม่สามารถแสดงผลหน้านี้ได้ กรุณาลองใหม่อีกครั้ง</p>" +
            "</body></html>");
    });
});

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment() || app.Environment.IsProduction())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseStaticFiles();                                  // ต้องมี ถ้าใช้ wwwroot
app.UseRouting();                                       // ต้องมาก่อน Cors/Auth
app.UseCors(AllowSpecificOriginWithCredentials);
app.UseAuthentication();                                // ต้องมาหลัง Routing, ก่อน Authorization
app.UseAuthorization();
app.UseSession();

// FIX (2026-08-15): this pattern was missing the trailing {id?} segment.
// PresentResultController.Result(string id) / VerifyResult() / VerifyScanQR()
// (VerifyScanQR has its own attribute route so it was unaffected) have no
// [Route] attribute, so they rely entirely on THIS conventional route to be
// reachable. ASP.NET Core's router requires the URL's segment count to match
// the template's — a 2-segment template ("{controller}/{action}") never
// matches a 3-segment URL like "/PresentResult/Result/{responseCode}", no
// matter what action/controller names are given. That request just fails to
// route at all (404 before MVC even selects a controller — [Authorize] never
// runs, no controller code runs), which is consistent with a browser-level
// "This page can't be found" rather than any app-rendered error page. This
// was likely the actual root cause of the /PresentResult/Result/{id}
// "redirect มาแล้วหน้า error" reports all along — the earlier [Authorize]
// fix on PresentResultController was a real bug too and stays fixed, but
// wouldn't have mattered on its own since the route never matched to begin
// with. VerifierController is unaffected — it's fully attribute-routed
// ([Route("openid4vc")] + per-action [Route(...)]), never relied on this.
app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Account}/{action=ThaIDLogin}/{id?}");
app.MapControllers();
app.Run();
