using System.Security.Cryptography;
using Microsoft.Extensions.Caching.Memory;
using VerifierService.Models;

namespace VerifierService.Services;

public class VerifierRequestService
{
    private readonly HttpClient _httpClient;
    private readonly IMemoryCache _cache;
    private readonly IConfiguration _configuration;
    private readonly ILogger<VerifierRequestService> _logger;
    private readonly DocumentTypeRegistry _documentTypeRegistry;

    // รายชื่อ host ของ Broker ที่เชื่อถือได้เท่านั้น — ป้องกัน SSRF
    // ห้ามยิง POST ไปที่ URL ใด ๆ ที่ QR บอกโดยไม่เช็คก่อน
    private readonly HashSet<string> _allowedBrokerHosts;

    public VerifierRequestService(
        HttpClient httpClient,
        IMemoryCache cache,
        IConfiguration configuration,
        ILogger<VerifierRequestService> logger,
        DocumentTypeRegistry documentTypeRegistry)
    {
        _httpClient = httpClient;
        _cache = cache;
        _configuration = configuration;
        _logger = logger;
        _documentTypeRegistry = documentTypeRegistry;

        var hosts = configuration.GetSection("AllowedBrokerHosts").Get<string[]>() ?? Array.Empty<string>();
        _allowedBrokerHosts = new HashSet<string>(hosts, StringComparer.OrdinalIgnoreCase);
    }

    public async Task<ScanResponse> HandleQrScanAsync(string scannedValue, string docType)
    {
        // 0. เช็คว่า docType ที่เจ้าหน้าที่เลือกมามีอยู่จริงใน registry ไหม
        if (!_documentTypeRegistry.TryGetDcqlQuery(docType, out var dcqlQuery))
        {
            _logger.LogWarning(
                "docType ไม่รู้จัก: {DocType} (ที่มีอยู่: {Available})",
                docType,
                string.Join(", ", _documentTypeRegistry.GetAvailableDocumentTypes()));
            return new ScanResponse { Success = false, Error = "unknown_doc_type" };
        }

        // 1. Validate ว่าเป็น URL ที่ถูกต้องก่อน
        if (!Uri.TryCreate(scannedValue, UriKind.Absolute, out var brokerUri))
        {
            _logger.LogWarning("QR scan ได้ค่าที่ไม่ใช่ URL ที่ถูกต้อง: {Value}", scannedValue);
            return new ScanResponse { Success = false, Error = "invalid_qr_content" };
        }

        // 2. เช็คว่า host อยู่ใน allowlist — ป้องกัน SSRF
        if (!_allowedBrokerHosts.Contains(brokerUri.Host))
        {
            _logger.LogWarning("QR ชี้ไปที่ host ที่ไม่ได้รับอนุญาต: {Host}", brokerUri.Host);
            return new ScanResponse { Success = false, Error = "untrusted_broker_endpoint" };
        }

        // 3. Generate nonce แบบ cryptographically secure — ห้ามใช้ Random ธรรมดา
        var nonce = GenerateSecureNonce();

        // 4. สร้าง transaction id ภายในของ Verifier เอง แล้วเก็บ nonce ไว้เทียบทีหลัง
        var txId = Guid.NewGuid().ToString();
        _cache.Set(
            $"pending-tx:{txId}",
            new PendingTransaction { TransactionId = txId, Nonce = nonce, CreatedAt = DateTimeOffset.UtcNow },
            TimeSpan.FromMinutes(5));

        // 5. สร้าง Authorization Request payload
        // response_uri เป็น dynamic route "verify/{id}" — ต้องแทน {id} ด้วย txId จริง
        // เพื่อให้ Verifier รู้ว่า VP Token ที่ได้กลับมาตรงกับ transaction ไหน
        var responseUriTemplate = _configuration["Verifier:ResponseUriTemplate"]
            ?? throw new InvalidOperationException("Verifier:ResponseUriTemplate not configured");
        var responseUri = responseUriTemplate.Replace("{id}", txId);

        var clientId = _configuration["Verifier:ClientId"]
            ?? throw new InvalidOperationException("Verifier:ClientId not configured");

        var authRequest = new AuthorizationRequestPayload
        {
            ClientId = clientId,
            ResponseUri = responseUri,
            Nonce = nonce,
            State = txId,
            DcqlQuery = dcqlQuery   // มาจาก DocumentTypeRegistry ตาม documentType ที่เจ้าหน้าที่เลือก
        };

        // 6. ส่งไปที่ Broker endpoint ที่ได้จาก QR
        try
        {
            var response = await _httpClient.PostAsJsonAsync(scannedValue, authRequest);

            if (!response.IsSuccessStatusCode)
            {
                var errorBody = await response.Content.ReadAsStringAsync();
                _logger.LogWarning(
                    "Broker ตอบกลับไม่สำเร็จ: {StatusCode} {Body}", response.StatusCode, errorBody);
                return new ScanResponse
                {
                    Success = false,
                    Error = $"broker_rejected_{(int)response.StatusCode}"
                };
            }

            return new ScanResponse { Success = true, TransactionId = txId };
        }
        catch (HttpRequestException ex)
        {
            _logger.LogError(ex, "ส่ง Authorization Request ไปที่ Broker ไม่สำเร็จ");
            return new ScanResponse { Success = false, Error = "broker_unreachable" };
        }
    }

    private static string GenerateSecureNonce()
    {
        var nonceBytes = RandomNumberGenerator.GetBytes(32);
        return Convert.ToBase64String(nonceBytes)
            .Replace("+", "-").Replace("/", "_").Replace("=", "");
    }
}
