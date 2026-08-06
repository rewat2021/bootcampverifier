namespace VerifierAPI.Services;

public interface IDocumentTypeRegistry
{
    bool TryGetConfig(string docType, out DocumentTypeConfig config);
    IEnumerable<string> GetAvailableDocumentTypes();
}

public class DocumentTypeConfig
{
    public string Format { get; set; } = default!;
    public string? DoctypeValue { get; set; }
    public string? VctValue { get; set; }
}

public class DocumentTypeRegistry : IDocumentTypeRegistry
{
    private readonly Dictionary<string, DocumentTypeConfig> _registry = new(StringComparer.OrdinalIgnoreCase)
    {
        ["driverlicense"] = new DocumentTypeConfig
        {
            Format = "mso_mdoc",
            DoctypeValue = "org.iso.18013.5.1.mDL"
        },
        ["nationalid"] = new DocumentTypeConfig
        {
            Format = "dc+sd-jwt",
            VctValue = "https://credentials.example.com/national_id"
        }
    };

    public bool TryGetConfig(string docType, out DocumentTypeConfig config)
        => _registry.TryGetValue(docType, out config!);

    public IEnumerable<string> GetAvailableDocumentTypes() => _registry.Keys;
}