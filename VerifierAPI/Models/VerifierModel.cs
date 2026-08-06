using Microsoft.AspNetCore.Mvc;
using System.Text.Json;

namespace VerifierAPI.Models
{
   
    public class VerifierModel 
    {

    }

    public class ScanRequest
    {
        public string ScannedValue { get; set; } = string.Empty;

        // ประเภทเอกสารที่เจ้าหน้าที่เลือกตอน trigger การสแกน
        // เช่น "driving_license", "national_id", "age_verification"
        public string DocType { get; set; } = string.Empty;
    }

    public class ScanResponse
    {
        public bool Success { get; set; }
        public string? TransactionId { get; set; }
        public string? SessionId { get; set; }
        public string? Error { get; set; }
        public string? OpenId4VpUri { get; set; }
    }

    public class AuthorizationRequestPayload
    {
        public string ClientId { get; set; } = string.Empty;
        public string ResponseType { get; set; } = "vp_token";
        public string ResponseMode { get; set; } = "direct_post";
        public string ResponseUri { get; set; } = string.Empty;
        public string Nonce { get; set; } = string.Empty;
        public JsonElement DcqlQuery { get; set; }
        public string State { get; set; } = string.Empty;

        // ประกาศว่า Verifier รองรับ credential format ไหนบ้าง
        // (Wallet ใช้ข้อมูลนี้เช็คก่อนว่ามี credential format ที่ตรงกันไหม ก่อนสร้าง presentation)
        public object? ClientMetadata { get; set; }
    }

    // เก็บไว้ใน cache เพื่อเทียบตอนรับ VP Token กลับที่ response_uri
    public class PendingTransaction
    {
        public string TransactionId { get; set; } = default!;
        public string Nonce { get; set; } = default!;
        public object RequestObject { get; set; } = default!;   // payload เต็มที่ Wallet จะมา fetch ทีหลัง
        public DateTimeOffset CreatedAt { get; set; }
    }

    // เก็บ config ของแต่ละประเภทเอกสาร (format + dcql query) — อ่านมาจาก document-types.json
    public class DocumentTypeConfig
    {
        public string Format { get; set; } = string.Empty;
        public JsonElement Dcql { get; set; }
    }

    public class DocumentTypeRegistry
    {
        private readonly Dictionary<string, DocumentTypeConfig> _configByDocumentType;
        private readonly ILogger<DocumentTypeRegistry> _logger;
        public DocumentTypeRegistry(IConfiguration configuration, ILogger<DocumentTypeRegistry> logger)
        {
            _logger = logger;
            var filePath = configuration["Verifier:DocumentTypesConfigPath"] ?? "document-types.json";
            var fullPath = Path.IsPathRooted(filePath)
                ? filePath
                : Path.Combine(AppContext.BaseDirectory, filePath);
            if (!File.Exists(fullPath))
            {
                throw new FileNotFoundException(
                    $"ไม่พบไฟล์ document-types config ที่ {fullPath} — ต้องมีไฟล์นี้เพื่อกำหนด DCQL query ของแต่ละประเภทเอกสาร");
            }
            var json = File.ReadAllText(fullPath);
            var parsed = JsonSerializer.Deserialize<Dictionary<string, DocumentTypeConfig>>(
                json, new JsonSerializerOptions { PropertyNameCaseInsensitive = true })
                ?? throw new InvalidOperationException("อ่านไฟล์ document-types config ไม่สำเร็จ (JSON ไม่ถูกต้อง)");
            _configByDocumentType = parsed;
            _logger.LogInformation(
                "โหลด document type config สำเร็จ: {Count} ประเภท ({Types})",
                _configByDocumentType.Count,
                string.Join(", ", _configByDocumentType.Keys));
        }

        public bool TryGetConfig(string documentType, out DocumentTypeConfig config)
        {
            return _configByDocumentType.TryGetValue(documentType, out config!);
        }
        public IEnumerable<string> GetAvailableDocumentTypes() => _configByDocumentType.Keys;
    }
}
