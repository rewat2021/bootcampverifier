using System;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using NLog;
using VerifierAPI.Databases;

namespace VerifierAPI.Filters
{
    // FEATURE (audit trail, 2026-08-15): records every VerifierVP call — success
    // AND every failure branch — to dbverifierlog, without touching that
    // method's existing (large, delicate, ~700-line) body. Implemented as an
    // action filter that runs AFTER the action executes and inspects the
    // returned IActionResult, instead of hand-instrumenting each of
    // VerifierVP's ~15 individual `return BadRequest(...)` points — much lower
    // regression risk on a method with no build/test coverage available this
    // session.
    //
    // Before this, only successful presentations were ever persisted anywhere
    // (Dbverifierresponse) — every failure (bad signature, DCQL mismatch,
    // replay, mdoc verify failed, expired/unknown/already-consumed session,
    // Wallet-declined, etc.) left no database trace at all, only an ephemeral
    // NLog file line with no retention policy. dbverifierlog already existed
    // as unused scaffolding (mapped in VerifierDbContext, real table in the
    // DB, but no code ever wrote to it) with almost exactly this shape —
    // reused here instead of adding a new table. See
    // OID4VP-1.0-COMPLIANCE-AUDIT.md and db/migrations/002_add_verifier_log_client_info.sql.
    //
    // Applied via [TypeFilter(typeof(VerifierAuditLogFilter))] on VerifierVP
    // only (see VerifierController.cs) — not global, so it doesn't fire for
    // unrelated endpoints. No DI registration needed: TypeFilterAttribute
    // constructs this per-request itself.
    //
    // LIMITATION: HolderDid/IssuerDid/Claims (columns that already exist on
    // dbverifierlog) are intentionally left null here — extracting them would
    // mean re-parsing vp_token/vc payload independently of VerifierVP's own
    // parsing (duplicated, drift-prone logic) rather than the 3 things the
    // user actually asked for (persist every outcome, capture IP/user-agent,
    // log retention). Follow-up if wanted.
    public class VerifierAuditLogFilter : IAsyncActionFilter
    {
        private static readonly Logger logger = LogManager.GetCurrentClassLogger();

        public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
        {
            var executedContext = await next();

            try
            {
                string? state = context.ActionArguments.TryGetValue("state", out var s) ? s as string : null;
                string? vpToken = context.ActionArguments.TryGetValue("vp_token", out var vp) ? vp as string : null;

                if (string.IsNullOrWhiteSpace(state))
                    return; // nothing meaningful to key the log entry to (e.g. required-field model binding failure before the action ran)

                bool? success = null;
                string? errorCode = null;
                string? errorMessage = null;

                // VerifierVP returns Ok(new { redirect_uri = ... }) (200) on success and
                // BadRequest(new { error, error_description, reason? }) (400) on every
                // failure branch — both are ObjectResult, so this one check covers all
                // ~15 return points uniformly.
                if (executedContext.Result is ObjectResult objResult && objResult.StatusCode.HasValue)
                {
                    success = objResult.StatusCode.Value == StatusCodes.Status200OK;
                    if (!success.Value)
                    {
                        var value = objResult.Value;
                        if (value != null)
                        {
                            var type = value.GetType();
                            errorCode = type.GetProperty("reason")?.GetValue(value) as string
                                ?? type.GetProperty("error")?.GetValue(value) as string;
                            errorMessage = type.GetProperty("error_description")?.GetValue(value) as string;
                        }
                    }
                }

                if (success == null)
                    return; // unrecognized result shape — skip rather than guess wrong

                using var dbContext = new VerifierDbContext();
                var session = dbContext.Dbverifiersessions.FirstOrDefault(x => x.Id == state);
                string? credentialType = null;
                if (session != null)
                {
                    var docType = dbContext.Dbdocumenttypes.FirstOrDefault(d => d.TypeId == session.DocTypeId);
                    credentialType = docType?.Format;
                }

                // On success, prefer what actually got persisted as the verified
                // credential (VcPayload/VpToken on Dbverifierresponse) over the raw
                // vp_token form field, since for mdoc that raw field is what's stored
                // anyway and for JWT/SD-JWT it's the same value either way.
                string? vpTokenToStore = vpToken;
                if (success.Value)
                {
                    var response = dbContext.Dbverifierresponses
                        .Where(r => r.SessionId == state)
                        .OrderByDescending(r => r.ReceivedAt)
                        .FirstOrDefault();
                    if (response != null)
                        vpTokenToStore = response.VcPayload ?? response.VpToken ?? vpToken;
                }

                string? clientIp = GetClientIp(context.HttpContext);
                string? userAgent = context.HttpContext.Request.Headers.UserAgent.ToString();
                if (!string.IsNullOrEmpty(userAgent) && userAgent.Length > 500)
                    userAgent = userAgent.Substring(0, 500);

                var entry = new Dbverifierlog
                {
                    // dbverifierlog.team_id is NOT NULL with no default — this
                    // deployment has no real multi-team concept, so use a fixed,
                    // configurable identifier for "this verifier instance".
                    TeamId = Environment.GetEnvironmentVariable("VERIFIER_TEAM_ID") ?? "default",
                    PresentationId = state,
                    CredentialType = credentialType,
                    Status = success.Value ? "success" : "failed",
                    Verified = success.Value,
                    ErrorCode = errorCode,
                    ErrorMessage = errorMessage,
                    VpToken = vpTokenToStore,
                    ClientIp = clientIp,
                    UserAgent = userAgent,
                    CreatedAt = DateTime.UtcNow
                };

                dbContext.Dbverifierlogs.Add(entry);
                dbContext.SaveChanges();
            }
            catch (Exception ex)
            {
                // audit logging must never break the actual verification response
                logger.Error(ex, "Failed to write verifier audit log");
            }
        }

        private static string? GetClientIp(HttpContext httpContext)
        {
            // this deployment sits behind a reverse proxy (see H-10 broker
            // host/port allowlisting) — prefer X-Forwarded-For when present.
            if (httpContext.Request.Headers.TryGetValue("X-Forwarded-For", out var xff) && !string.IsNullOrWhiteSpace(xff))
            {
                // may contain multiple IPs (client, proxy1, proxy2, ...) — take the first
                var first = xff.ToString().Split(',')[0].Trim();
                if (!string.IsNullOrEmpty(first)) return first;
            }
            return httpContext.Connection.RemoteIpAddress?.ToString();
        }
    }
}
