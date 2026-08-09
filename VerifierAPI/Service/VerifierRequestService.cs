using VerifierAPI.Models;
using VerifierAPI.Service;

namespace VerifierAPI.Services;

public class VerifierRequestService
{
    private readonly HttpClient _httpClient;
    private readonly HashSet<string> _allowedBrokerHosts;
    private readonly ILogger<VerifierRequestService> _logger;

    public VerifierRequestService(
        HttpClient httpClient,
        IConfiguration config,
        ILogger<VerifierRequestService> logger)
    {
        _httpClient = httpClient;
        _logger = logger;

        _allowedBrokerHosts = (config.GetSection("AllowedBrokerHosts").Get<string[]>() ?? Array.Empty<string>())
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
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
        if (brokerUri.Port != 443)
        {
            _logger.LogWarning("QR ชี้ไปที่ port ที่ไม่ใช่ HTTPS default (443): {Value}", scannedValue);
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
        var clientId = $"redirect_uri:{baseUrl}/openid4vc/verify/{stateId}";
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