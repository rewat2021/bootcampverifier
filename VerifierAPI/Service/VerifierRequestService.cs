using VerifierAPI.Models;
using VerifierAPI.Service;

namespace VerifierAPI.Services;

public class VerifierRequestService
{
    private readonly HttpClient _httpClient;
    private readonly HashSet<string> _allowedBrokerHosts;
    // FIX (H-10 follow-up, 2026-08-11): was hardcoded to require exactly port
    // 443, which blocked real broker deployments running HTTPS on a
    // non-standard port (e.g. behind a reverse proxy / container port mapping)
    // — a legitimate, common setup that has nothing to do with the SSRF/TLS
    // risk H-10 was actually about. Now configurable via AllowedBrokerPorts
    // (defaults to [443] if unset, preserving the original strict behavior for
    // anyone who hasn't configured it) — the host allowlist below is still the
    // primary SSRF defense either way. See OID4VP-1.0-COMPLIANCE-AUDIT.md
    // finding H-10.
    private readonly HashSet<int> _allowedBrokerPorts;
    private readonly ILogger<VerifierRequestService> _logger;
    // FIX (H-01, 2026-08-10/11): needed to compute the Verifier's did:key
    // client_id via VCService.GetVerifierClientId, the same key/DID RequestURI
    // signs with — see this file's own comment below for why this must match.
    private readonly IWebHostEnvironment _env;

    public VerifierRequestService(
        HttpClient httpClient,
        IConfiguration config,
        ILogger<VerifierRequestService> logger,
        IWebHostEnvironment env)
    {
        _httpClient = httpClient;
        _logger = logger;
        _env = env;

        _allowedBrokerHosts = (config.GetSection("AllowedBrokerHosts").Get<string[]>() ?? Array.Empty<string>())
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var configuredPorts = config.GetSection("AllowedBrokerPorts").Get<int[]>();
        _allowedBrokerPorts = (configuredPorts != null && configuredPorts.Length > 0
            ? configuredPorts
            : new[] { 443 }).ToHashSet();
    }

    public async Task<ScanResponse> HandleQrScanAsync(
        string scannedValue, string docType, string baseUrl, string sessionId, HttpRequest Request)
    {
        // 1. Validate URL
        if (!Uri.TryCreate(scannedValue, UriKind.Absolute, out var brokerUri))
        {
            _logger.LogWarning("QR scan ได้ค่าที่ไม่ใช่ URL ที่ถูกต้อง: {Value}", scannedValue);
            return new ScanResponse { Success = false, Error = "invalid_qr_content" };
        }

        // FIX (H-10, 2026-08-09): only the host name was checked before — scheme,
        // port, and embedded userinfo were unconstrained, so http://, non-default
        // ports, and userinfo-smuggled URLs (https://allowed-host@evil/..., where
        // some parsers/humans misread the real target) all passed. OpenID4VP
        // requires current TLS best practices (§14.6).
        // See OID4VP-1.0-COMPLIANCE-AUDIT.md finding H-10.
        if (!string.Equals(brokerUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            _logger.LogWarning("QR ชี้ไปที่ URL ที่ไม่ใช่ HTTPS: {Value}", scannedValue);
            return new ScanResponse { Success = false, Error = "untrusted_broker_endpoint" };
        }
        if (!string.IsNullOrEmpty(brokerUri.UserInfo))
        {
            _logger.LogWarning("QR URL มี userinfo ฝังอยู่ ปฏิเสธ: {Value}", scannedValue);
            return new ScanResponse { Success = false, Error = "untrusted_broker_endpoint" };
        }
        if (!_allowedBrokerPorts.Contains(brokerUri.Port))
        {
            _logger.LogWarning("QR ชี้ไปที่ port ที่ไม่ได้รับอนุญาต ({Port}): {Value}", brokerUri.Port, scannedValue);
            return new ScanResponse { Success = false, Error = "untrusted_broker_endpoint" };
        }

        // 2. เช็ค allowlist กัน SSRF
        if (!_allowedBrokerHosts.Contains(brokerUri.Host))
        {
            _logger.LogWarning("QR ชี้ไปที่ host ที่ไม่ได้รับอนุญาต: {Host}", brokerUri.Host);
            return new ScanResponse { Success = false, Error = "untrusted_broker_endpoint" };
        }

        // 3. สร้าง session ใน DB ผ่าน DBService เดิม (validate docType ให้ในตัว — throw ถ้าไม่เจอ)
        var dbServ = new DBService();
        string stateId;
        try
        {
            var session = dbServ.SaveVerifierSession(docType);
            stateId = session.stateId;
        }
        catch (ArgumentException ex)
        {
            _logger.LogWarning(ex, "docType ไม่รู้จัก: {DocType}", docType);
            return new ScanResponse { Success = false, Error = "unknown_doc_type" };
        }

        // 4. สร้าง URI สั้น — request_uri ชี้ไปที่ endpoint เดิม (VerifierController.RequestURI)
        //    ซึ่งจะดึง dcql_query/client_metadata จาก Dbverifiersession + Dbdocumenttype เอง
        // FIX (H-01, 2026-08-10/11) — CORRECTED: client_id here used to be
        // `redirect_uri:...`. RequestURI now signs its Request Object with the
        // Verifier's ES256/P-256 key (VCService.SignRequestObjectES256, as of
        // 2026-08-11 — briefly Ed25519 on 2026-08-10, reverted per explicit
        // instruction) and uses a `decentralized_identifier:did:key:...`
        // client_id instead (OpenID4VP §5.9.3 — the redirect_uri Client
        // Identifier Prefix cannot be signed; `decentralized_identifier` is the
        // spec's actual prefix name for a DID-bound client_id, confirmed against
        // the published spec text — an earlier version of this fix used the bare
        // DID with no prefix, which a real Wallet rejected). Per RFC 9101 §5,
        // this outer client_id sent to the broker MUST match the client_id inside
        // the Request Object once dereferenced, so this calls the same
        // VCService.GetVerifierClientId used by RequestURI instead of building
        // its own string. See OID4VP-1.0-COMPLIANCE-AUDIT.md finding H-01.
        var clientId = new VCService().GetVerifierClientId(_env);
        var requestUri = $"{baseUrl}/openid4vc/request/{stateId}";
        var openId4VpUri = BuildShortOpenId4VpUri(clientId, requestUri);

        // 5. ส่ง URI สั้นนี้ไปที่ Broker (ห่อเป็น JSON เพราะ Broker รับ JsonElement)
        try
        {
            var brokerPayload = new { request_uri = openId4VpUri };
            var response = await _httpClient.PostAsJsonAsync(scannedValue, brokerPayload);

            // FIX (H-10, 2026-08-09): reject unexpectedly large broker responses
            // rather than buffering an unbounded amount of attacker-controlled data.
            // Only guards responses that declare Content-Length; a broker that omits
            // it or streams chunked is still bounded by the client Timeout above.
            const long maxResponseBytes = 1_048_576; // 1 MB
            if (response.Content.Headers.ContentLength is long contentLength && contentLength > maxResponseBytes)
            {
                _logger.LogWarning("Broker ตอบกลับข้อมูลใหญ่เกินกำหนด: {Length} bytes", contentLength);
                return new ScanResponse { Success = false, Error = "broker_response_too_large" };
            }

            if (!response.IsSuccessStatusCode)
            {
                var errorBody = await response.Content.ReadAsStringAsync();
                _logger.LogWarning("Broker ตอบกลับไม่สำเร็จ: {StatusCode} {Body}", response.StatusCode, errorBody);
                return new ScanResponse { Success = false, Error = $"broker_rejected_{(int)response.StatusCode}" };
            }

            return new ScanResponse
            {
                Success = true,
                TransactionId = stateId,
                OpenId4VpUri = openId4VpUri
            };
        }
        catch (HttpRequestException ex)
        {
            _logger.LogError(ex, "ส่ง Authorization Request ไปที่ Broker ไม่สำเร็จ");
            return new ScanResponse { Success = false, Error = "broker_unreachable" };
        }
    }

    private static string BuildShortOpenId4VpUri(string clientId, string requestUri)
    {
        var query = new Dictionary<string, string>
        {
            ["client_id"] = clientId,
            ["request_uri"] = requestUri
        };

        var queryString = string.Join("&", query.Select(kv =>
            $"{kv.Key}={Uri.EscapeDataString(kv.Value)}"));

        return $"openid4vp://authorize?{queryString}";
    }
}