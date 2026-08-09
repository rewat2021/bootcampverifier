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
        var result = context.Dbverifierresponses
            .Where(r => r.SessionId == sessionId)
            .FirstOrDefault();

        // ยังไม่มีแถวเลย = wallet ยังไม่ได้ส่งอะไรกลับมา
        if (result == null || (string.IsNullOrWhiteSpace(result.VpToken) && string.IsNullOrWhiteSpace(result.VcPayload)))
            return Ok(new { status = "pending" });

        // TODO: ตอนนี้เดาว่า "มีแถว + มี payload" = ตรวจผ่านเสมอ
        // ถ้าตาราง Dbverifierresponses มีคอลัมน์บอกผลจริง (เช่น IsValid, ErrorReason,
        // VerificationStatus) ควรใช้ค่านั้นตัดสิน แทนการเดาจากแค่ "มีข้อมูลหรือไม่"
        // บรรทัดด้านล่างสมมติว่ามีคอลัมน์ชื่อ ErrorReason — ถ้าไม่มีให้ลบทิ้ง
        //if (!string.IsNullOrWhiteSpace(result.ErrorReason))
        //{
        //    return Ok(new { status = "failed", error = result.ErrorReason });
        //}

        var claims = ParseClaimsFromVcPayload(result.VcPayload);
        return Ok(new { status = "completed", claims });
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
