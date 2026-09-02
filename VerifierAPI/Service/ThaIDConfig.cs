using Microsoft.Extensions.Configuration;

namespace VerifierAPI.Service
{
    /// <summary>
    /// Strongly-typed options bound from the "ThaIDConfig" section in appsettings.json
    /// (ClientSecret should come from User Secrets / Environment Variable / Key Vault,
    /// not committed to appsettings.json).
    /// </summary>
    public class ThaIDOptions
    {
        public string GatewayBaseUrl { get; set; } = string.Empty;
        public string ClientID { get; set; } = string.Empty;
        public string ClientSecret { get; set; } = string.Empty;
        public string RedirectURL { get; set; } = string.Empty;
    }

    /// <summary>
    /// Static accessor kept for compatibility with existing code that calls
    /// ThaIDConfig.ClientID / ThaIDConfig.ClientSecret / ThaIDConfig.GatewayBaseUrl directly.
    /// Must be initialized once at startup via ThaIDConfig.Configure(...) in Program.cs.
    /// </summary>
    public static class ThaIDConfig
    {
        private static ThaIDOptions _options = new ThaIDOptions();

        public static void Configure(IConfiguration configuration)
        {
            _options = configuration.GetSection("ThaIDConfig").Get<ThaIDOptions>()
                       ?? new ThaIDOptions();
        }

        public static string GatewayBaseUrl => _options.GatewayBaseUrl;
        public static string ClientID => _options.ClientID;
        public static string ClientSecret => _options.ClientSecret;
        public static string RedirectURL => _options.RedirectURL;
    }
}
