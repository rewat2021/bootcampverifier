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