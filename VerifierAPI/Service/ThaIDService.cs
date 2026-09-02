using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text.Json;
using NLog;

namespace VerifierAPI.Service
{
    public class ThaIDTokenResponse
    {
        public string AccessToken { get; set; }
        public string IDToken { get; set; }
        public string TokenType { get; set; }
        public int ExpiresIn { get; set; }
    }

    public class ThaIDProfile
    {
        public string TitleNameTh { get; set; }
        public string FirstNameTh { get; set; }
        public string LastNameTh { get; set; }
        public string TitleNameEn { get; set; }
        public string FirstNameEn { get; set; }
        public string LastNameEn { get; set; }
        public string BirthDate { get; set; }
        public string Gender { get; set; }
    }

    // SECURITY (2026-08-27): client for the real DOPA ThaID API v2 token endpoint.
    // Added so AccountController.ThaiIDCallback can exchange the authorization
    // `code` it receives for an id_token server-to-server (using ThaIDConfig's
    // client_id + client_secret), instead of the previous ThaIDSignIn endpoint
    // which trusted a bare `pid` query-string value with no proof it actually
    // came from ThaID at all — see the conversation/audit notes on that finding.
    //
    // DOPA's v2 API embeds the citizen id (pid) and basic profile directly as
    // claims inside the returned id_token JWT, so GetCitizenId/GetProfile just
    // decode that token rather than making a second userinfo call.
    //
    // NOTE: the token-endpoint path below, and the id_token claim names in
    // GetCitizenId/GetProfile, follow the published DOPA ThaID API v2 OIDC
    // convention but have not been verified against a live DOPA sandbox
    // response from inside this session. GetCitizenId falls back from "pid" to
    // the standard OIDC "sub" claim, and every method logs every claim name
    // actually present in the id_token whenever the expected claim isn't found
    // — so a naming mismatch shows up immediately in the app log (nlog) instead
    // of silently failing. Confirm against a real DOPA response before relying
    // on this in production, and adjust the claim-name lookups below if needed.
    //
    // Deliberately does NOT verify the id_token's JWS signature against DOPA's
    // JWKS (that endpoint isn't documented in this codebase either) — the
    // token was obtained via a direct, client-secret-authenticated HTTPS call
    // to DOPA's own token endpoint, not handed to us by the browser, so the
    // main spoofing risk (a forged token) is already mitigated at that layer.
    // Full JWKS signature verification would still be the more complete fix if
    // DOPA's JWKS endpoint gets confirmed later.
    public class ThaIDService
    {
        private static readonly Logger logger = LogManager.GetCurrentClassLogger();
        private readonly HttpClient _httpClient;

        private const string TokenEndpoint = "https://imauth.bora.dopa.go.th/api/v2/oauth2/token/";

        public ThaIDService(HttpClient httpClient)
        {
            _httpClient = httpClient;
        }

        public async Task<ThaIDTokenResponse> GetAccessTokenAsync(string code, string redirectUri)
        {
            var form = new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["code"] = code,
                ["redirect_uri"] = redirectUri,
                ["client_id"] = ThaIDConfig.ClientID,
                ["client_secret"] = ThaIDConfig.ClientSecret
            };

            string body;
            try
            {
                using var response = await _httpClient.PostAsync(TokenEndpoint, new FormUrlEncodedContent(form));
                body = await response.Content.ReadAsStringAsync();

                if (!response.IsSuccessStatusCode)
                {
                    logger.Error($"ThaID token endpoint returned {(int)response.StatusCode}: {body}");
                    return null;
                }
            }
            catch (Exception e)
            {
                logger.Error(e, "ThaID token endpoint request failed");
                return null;
            }

            try
            {
                using var doc = JsonDocument.Parse(body);
                var root = doc.RootElement;
                return new ThaIDTokenResponse
                {
                    AccessToken = root.TryGetProperty("access_token", out var at) ? at.GetString() : null,
                    IDToken = root.TryGetProperty("id_token", out var idt) ? idt.GetString() : null,
                    TokenType = root.TryGetProperty("token_type", out var tt) ? tt.GetString() : null,
                    ExpiresIn = root.TryGetProperty("expires_in", out var ei) && ei.TryGetInt32(out var eiVal) ? eiVal : 0
                };
            }
            catch (Exception e)
            {
                logger.Error(e, $"ThaID token endpoint returned a non-JSON or unexpected body: {body}");
                return null;
            }
        }

        public string GetCitizenId(ThaIDTokenResponse token)
        {
            var claims = ReadIdTokenClaims(token);
            if (claims == null) return null;

            // DOPA's own docs use "pid"; fall back to the standard OIDC "sub"
            // claim in case the deployed gateway follows plain OIDC naming instead.
            var pid = claims.FirstOrDefault(c => c.Type == "pid")?.Value
                      ?? claims.FirstOrDefault(c => c.Type == "sub")?.Value;

            if (string.IsNullOrWhiteSpace(pid))
            {
                logger.Warn("ThaID id_token had no 'pid' or 'sub' claim. Claims present: " +
                            string.Join(", ", claims.Select(c => c.Type)));
            }
            return pid;
        }

        public ThaIDProfile GetProfile(ThaIDTokenResponse token)
        {
            var claims = ReadIdTokenClaims(token);
            if (claims == null) return null;

            string Get(params string[] types) =>
                types.Select(t => claims.FirstOrDefault(c => c.Type == t)?.Value)
                     .FirstOrDefault(v => !string.IsNullOrWhiteSpace(v));

            return new ThaIDProfile
            {
                TitleNameTh = Get("title_th", "title"),
                FirstNameTh = Get("given_name", "first_name_th"),
                LastNameTh = Get("family_name", "last_name_th"),
                TitleNameEn = Get("title_en"),
                FirstNameEn = Get("given_name_en", "first_name_en"),
                LastNameEn = Get("family_name_en", "last_name_en"),
                BirthDate = Get("birthdate"),
                Gender = Get("gender")
            };
        }

        private IList<Claim> ReadIdTokenClaims(ThaIDTokenResponse token)
        {
            if (string.IsNullOrWhiteSpace(token?.IDToken))
            {
                logger.Warn("ReadIdTokenClaims: no id_token present on the ThaID token response");
                return null;
            }
            try
            {
                var handler = new JwtSecurityTokenHandler();
                var jwt = handler.ReadJwtToken(token.IDToken);
                return jwt.Claims.ToList();
            }
            catch (Exception e)
            {
                logger.Error(e, "Failed to parse ThaID id_token as JWT");
                return null;
            }
        }
    }
}
