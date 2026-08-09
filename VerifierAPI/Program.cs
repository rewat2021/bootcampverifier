using Microsoft.AspNetCore.Authentication.Cookies;
using NLog;
using NLog.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using VerifierAPI.Service;

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
                    policy.WithOrigins(new string[] { "https://wallet-test.etda.or.th", "https://issuer-cu-test.etda.or.th", "https://issuer.zenithcomp.co.th:455",
                        "https://vc-testtool.etda.or.th", "https://vc-testtool-test.etda.or.th", "https://verifier.zenithcomp.co.th:455", "https://wallet.zenithcomp.co.th:455" }) // Replace with your allowed origins
                           .AllowAnyHeader()
                           .AllowAnyMethod();
                    //.AllowCredentials(); // This enables Access-Control-Allow-Credentials
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


var app = builder.Build();

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

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Account}/{action=ThaIDLogin}");
app.MapControllers();
app.Run();
