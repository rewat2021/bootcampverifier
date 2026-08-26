using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using VerifierAPI.Models;
using VerifierAPI.Services;
using VerifierAPI.Databases;
using Newtonsoft.Json;
using NLog;

namespace VerifierAPI.Controllers;

// SECURITY (H-08 remediation, 2026-08-09): both actions here are driven by the
// verifier operator's own browser/terminal session (VerifyScanQR.cshtml scans a
// physical QR then calls these — the Wallet never calls this controller directly,
// it only ever talks to VerifierController's request/{id} and verify/{id}). Status
// previously returned decoded claims for any session ID with no login requirement.
// See OID4VP-1.0-COMPLIANCE-AUDIT.md finding H-08.
[Authorize]
[ApiController]
[Route("verifier")]
public class VerifierScanController : ControllerBase
{
    private readonly VerifierRequestService _requestService;
    private readonly ILogger<VerifierController> _logger;

    public VerifierScanController(VerifierRequestService requestService, ILogger<VerifierController> logger)
    {
        _requestService = requestService;
        _logger = logger;
    }


    // POST /verifier/scan
    // รับค่าที่อ่านได้จาก QR (จากเว็บ/แอปที่ใช้กล้องสแกน) แล้ว
    // generate nonce + สร้าง Authorization Request + ส่งไปที่ Broker
    [HttpPost("scan")]
    [Produces("text/plain")]
    public async Task<IActionResult> HandleQrScan([FromBody] ScanRequest req)
    {
        if (string.IsNullOrWhiteSpace(req.ScannedValue))
            return BadRequest("empty_scanned_value");
        if (string.IsNullOrWhiteSpace(req.DocType))
            return BadRequest("doc_type_required");

        var sessionId = ExtractSessionId(req.ScannedValue);
        if (sessionId is null)
            return BadRequest("invalid_qr_content");

        var baseUrl = $"{Request.Scheme}://{Request.Host}";
        var result = await _requestService.HandleQrScanAsync(req.ScannedValue, req.DocType, baseUrl, sessionId, Request);

        if (!result.Success)
        {
            return result.Error switch
            {
                "invalid_qr_content" => BadRequest(result.Error),
                "unknown_doc_type" => BadRequest(result.Error),
                "untrusted_broker_endpoint" => StatusCode(403, result.Error),
                "broker_unreachable" => StatusCode(502, result.Error),
                _ => StatusCode(500, result.Error)
            };
        }

        // return เป็น raw openid4vp:// URI string ตรง ๆ ไม่ wrap เป็น JSON
        return Content(result.OpenId4VpUri, "text/plain");
    }

    // ดึง sessionId จาก path ของ URL รูปแบบ /broker/session/{sessionId}/request
    private static string? ExtractSessionId(string scannedValue)
    {
        if (!Uri.TryCreate(scannedValue, UriKind.Absolute, out var uri))
            return null;

        var segments = uri.AbsolutePath.Trim('/').Split('/');
        // คาดหวัง path: broker/session/{sessionId}/request
        var sessionIndex = Array.IndexOf(segments, "session");
        if (sessionIndex >= 0 && sessionIndex + 1 < segments.Length)
            return segments[sessionIndex + 1];

        return null;
    }

    [HttpGet("/verifier/status/{sessionId}")]
    public IActionResult GetScanStatus(string sessionId)
    {
        if (string.IsNullOrWhiteSpace(sessionId))
            return BadRequest(new { status = "failed", error = "missing_session_id" });

        var context = new VerifierDbContext();

        // FIX (M-04 remediation, 2026-08-23): this used to infer status purely from
        // whether a Dbverifierresponse row existed — "Wallet hasn't answered yet" and
        // "Wallet answered but verification failed" both showed as "pending" forever
        // (until the session's own 10-minute expiry), because
        // VerifierController.VerifierVP only ever wrote a response row on a
        // successful verification. Every verify-failure path there now marks
        // session.Status = "Failed" (see VerifierVP's FailSession local function), so
        // read the session's own status as the source of truth here instead of
        // continuing to guess from row presence — this is also what lets the existing
        // frontend polling in VerifyScanQR.cshtml (which already checks
        // `data.status === 'failed'` and shows a rejection screen) actually fire.
        // Reports the four explicit states the original audit (M-03) called for:
        // pending / completed / failed / expired.
        // See OID4VP-1.0-COMPLIANCE-AUDIT.md finding M-04.
        var session = context.Dbverifiersessions.Where(s => s.Id == sessionId).FirstOrDefault();
        if (session == null)
            return Ok(new { status = "unknown" });

        if (string.Equals(session.Status, "Failed", StringComparison.OrdinalIgnoreCase))
            return Ok(new { status = "failed", error = "verification_failed" });

        if (string.Equals(session.Status, "Consumed", StringComparison.OrdinalIgnoreCase))
        {
            var result = context.Dbverifierresponses
                .Where(r => r.SessionId == sessionId)
                .FirstOrDefault();

            if (result == null || (string.IsNullOrWhiteSpace(result.VpToken) && string.IsNullOrWhiteSpace(result.VcPayload)))
            {
                // Consumed but no usable payload persisted — shouldn't normally happen
                // (VerifierVP writes the response row and consumes the session in the
                // same SaveChanges call), but don't report "completed" without a
                // payload to back it up.
                return Ok(new { status = "failed", error = "missing_result" });
            }

            var claims = ParseClaimsFromVcPayload(result.VcPayload);
            // FIX (M-02, 2026-08-09): PresentResult/Result now looks results up by the
            // freshly generated ResponseCode instead of the session id (see
            // VerifierController.VerifierVP), so the polling JS that navigates the
            // operator's browser there needs this code, not the session id it already
            // has. See OID4VP-1.0-COMPLIANCE-AUDIT.md finding M-02.
            return Ok(new { status = "completed", claims, response_code = result.ResponseCode });
        }

        // Status is "Pending" — still waiting on the Wallet, unless the session
        // itself has expired in the meantime.
        if (session.ExpiresAt < DateTime.UtcNow)
            return Ok(new { status = "expired" });

        return Ok(new { status = "pending" });
    }

    private static Dictionary<string, object> ParseClaimsFromVcPayload(string? vcPayload)
    {
        if (string.IsNullOrWhiteSpace(vcPayload))
            return new Dictionary<string, object>();

        try
        {
            return JsonConvert.DeserializeObject<Dictionary<string, object>>(vcPayload)
                   ?? new Dictionary<string, object>();
        }
        catch
        {
            return new Dictionary<string, object>
            {
                ["raw_payload"] = vcPayload
            };
        }
    }
}
