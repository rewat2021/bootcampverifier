using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using NLog;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Utilities;
using System;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using VerifierAPI.Databases;
using VerifierAPI.Filters;
using VerifierAPI.Models;
using VerifierAPI.Service;

namespace VerifierAPI.Controllers
{
    [ApiController]
    [Route("openid4vc")]
    public class VerifierController : ControllerBase
    {

        private readonly ILogger<VerifierController> _logger;
        private static readonly Logger logger = LogManager.GetCurrentClassLogger();
        private string baseUrl = Environment.GetEnvironmentVariable("INTERNAL_BASE_URL");
        // FIX (H-01, 2026-08-10): needed to read/persist the Verifier's ES256
        // Request Object signing key (see VCService.GetVerifierRequestSigningKey),
        // which is stored as a PEM file under ContentRootPath, same pattern as the
        // existing Ed25519 key(s).
        private readonly IWebHostEnvironment _env;


        public VerifierController(ILogger<VerifierController> logger, IWebHostEnvironment env)
        {
            _logger = logger;
            _env = env;
        }

        // FIX (M-08, 2026-08-09): removed a commented-out earlier version of
        // VerifierPresentVP (superseded by the active version below, which adds
        // URL-encoding and the same-device deeplink). See M-08 in the audit.

        // FIX (H-01, 2026-08-09) — SUPERSEDED 2026-08-10: an earlier version of this
        // method embedded the full authorization request (dcql_query +
        // client_metadata as URL-encoded JSON, in addition to the other params)
        // directly into the QR-encoded URI, to avoid the Wallet dereferencing
        // RequestURI and getting back an unsecured (alg:none) Request Object.
        // That worked, but produced a QR code dense enough to be unreliable to
        // scan in practice.
        //
        // RequestURI signs its Request Object with the Verifier's own key (as of
        // 2026-08-11, ES256/P-256 — see VCService.SignRequestObjectES256 /
        // GetVerifierDid, finding H-01; briefly Ed25519 on 2026-08-10, reverted
        // per explicit instruction), so there's no reason to avoid the
        // by-reference request_uri form — it's small (just client_id +
        // request_uri) *and* secure. This also means the direct-QR flow and the
        // broker-relay flow (VerifierScanController/VerifierRequestService)
        // share the exact same signed Request Object logic instead of diverging.
        //
        // FIX (H-01, 2026-08-10) — CORRECTED: client_id here is now
        // `decentralized_identifier:did:key:...` (VCService.GetVerifierClientId),
        // not `redirect_uri:...` — per OpenID4VP §5.9.3, "requests using the
        // redirect_uri Client Identifier Prefix cannot be signed because there is
        // no method for the Wallet to obtain a trusted key for verification." An
        // earlier version of this fix used the bare DID with no prefix at all
        // (matches no defined Client Identifier Prefix — corrected after a real
        // Wallet rejected it with a version-inference error).
        // Per RFC 9101 §5, this outer client_id MUST match the client_id inside
        // the Request Object once the Wallet dereferences request_uri, so this
        // must stay in sync with what RequestURI puts in the signed payload.
        // See OID4VP-1.0-COMPLIANCE-AUDIT.md finding H-01.
        [Route("/generate-vp-qr")]
        [HttpPost]
        public IActionResult VerifierPresentVP([FromBody] GenerateVpQrRequest docType)
        {
            VCService vcServ = new VCService();
            DBService dbServ = new DBService();

            baseUrl = Environment.GetEnvironmentVariable("INTERNAL_BASE_URL")
              ?? $"{Request.Scheme}://{Request.Host}";
            VpRequestSession model = dbServ.SaveVerifierSession(docType.DocumentType.ToString());
            string nonce = model.nonce;
            string stateid = model.stateId;

            string request_uri = $"{baseUrl}/openid4vc/request/{stateid}";
            string clientId = vcServ.GetVerifierClientId(_env);

            // สำคัญ: ต้อง URL-encode ค่าที่มี :, /, & ปนอยู่ ไม่งั้น Wallet parse query string ผิด
            // (ตรงกับตัวอย่างในสเปก client_id=redirect_uri%3Ahttps%3A%2F%2F...)
            string encodedParams =
                $"client_id={Uri.EscapeDataString(clientId)}" +
                $"&request_uri={Uri.EscapeDataString(request_uri)}";

            // ใช้สำหรับ QR (cross device) — Wallet ทั่วไปที่รองรับ openid4vp:// ตามสเปก
            string authorizationRequestUri = "openid4vp://authorize?" + encodedParams;

            // ใช้สำหรับปุ่ม deeplink (same device) — scheme เฉพาะของแอป Wallet นี้
            string deeplinkUri = "walletapp://callback?" + encodedParams;

            string QRCode = vcServ.GenerateQrCodeBase64(authorizationRequestUri);

            var response = new GenerateVpQrResponse
            {
                AuthorizationRequestUri = authorizationRequestUri, // ยังคงไว้เผื่อของเดิมใช้อยู่
                DeeplinkUri = deeplinkUri,                          // ใหม่ - ใช้กับปุ่ม same-device
                QrText = authorizationRequestUri,
                QrImageBase64 = QRCode,
                State = stateid,
                Nonce = nonce
            };

            return Ok(response);
        }

        // FIX (H-01/H-03, 2026-08-09): shared client_metadata builder used by both
        // VerifierPresentVP (direct-encoded request) and RequestURI. Kept as one
        // place so the H-03 format-specific alg field-name fix doesn't have to be
        // duplicated and drift between the two.
        // (2026-08-10: this briefly took an optional jwksUri parameter while
        // RequestURI signed with ES256 — reverted, see RequestURI's comment below.)
        private object BuildClientMetadata(Dbdocumenttype docType)
        {
            var algValues = JsonConvert.DeserializeObject<string[]>(docType.AlgValues);
            bool isSdJwtFormat = string.Equals(docType.Format, "dc+sd-jwt", StringComparison.OrdinalIgnoreCase)
                || string.Equals(docType.Format, "vc+sd-jwt", StringComparison.OrdinalIgnoreCase);
            bool isMdocFormat = string.Equals(docType.Format, "mso_mdoc", StringComparison.OrdinalIgnoreCase);
            // FIX (H-01 follow-up / NFC-mdoc support, 2026-08-11): mso_mdoc's
            // vp_formats_supported entry uses issuerauth_alg_values/
            // deviceauth_alg_values (OpenID4VP Appendix B.2.2), not alg_values —
            // -7 is the COSE identifier for ES256, the only IssuerAuth/DeviceAuth
            // algorithm this deployment's mdoc verifier (MdocService) supports.
            // See OID4VP-1.0-COMPLIANCE-AUDIT.md finding H-01.
            object formatMetadata = isSdJwtFormat
                ? new Dictionary<string, object>
                    {
                        ["sd-jwt_alg_values"] = algValues,
                        ["kb-jwt_alg_values"] = new[] { "EdDSA", "ES256" }
                    }
                : isMdocFormat
                ? new Dictionary<string, object>
                    {
                        ["issuerauth_alg_values"] = new[] { -7 },
                        ["deviceauth_alg_values"] = new[] { -7 }
                    }
                : new { alg_values = algValues };

            return new
            {
                vp_formats_supported = new Dictionary<string, object>
                {
                    [docType.Format] = formatMetadata
                }
            };
        }

        // FIX (M-08, 2026-08-09): removed three unused private methods
        // (BuildDcqlQuery(DocumentType), BuildPresentationDefinition(Dbdocumenttype),
        // BuildDcqlQuery(string)) — none were called anywhere; the active DCQL
        // builder is VCService.BuildDcqlQuery(Dbdocumenttype, HttpRequest), used
        // below in RequestURI. See OID4VP-1.0-COMPLIANCE-AUDIT.md finding M-08.

        // FIX (H-01, 2026-08-09/2026-08-10): both the direct-QR flow
        // (VerifierPresentVP, above) and the broker-relay flow
        // (VerifierRequestService.HandleQrScanAsync, reached via
        // VerifierScanController) reach this endpoint by reference
        // (client_id+request_uri).
        //
        // The Request Object served here is signed — this stops in-transit
        // tampering with the request (e.g. rewriting response_uri to redirect a
        // VP presentation to an attacker). Signed with the Verifier's ES256/P-256
        // did:key (VCService.SignRequestObjectES256 / GetVerifierRequestSigningKey)
        // as of 2026-08-11, per explicit instruction to switch client_id and kid
        // back to ES256. Briefly Ed25519 (VCService.SignRequestObject / _GetDID,
        // still defined but unused) on 2026-08-10, after a real Wallet failed to
        // verify the P-256 signature — but that failure coincided with a
        // client_id/kid DID-mismatch bug (see below) that alone would guarantee
        // a verification failure, so it's not yet confirmed the P-256 curve
        // itself was ever actually the problem. This revert has not been
        // re-tested against a live Wallet.
        //
        // client_id is `decentralized_identifier:did:key:...` (not
        // `redirect_uri:...`) — per OpenID4VP §5.9.3, requests using the
        // `redirect_uri` Client Identifier Prefix "cannot be signed because there
        // is no method for the Wallet to obtain a trusted key for verification."
        // An earlier version used the bare DID with no prefix at all — that
        // matches none of the spec's defined Client Identifier Prefixes and was
        // rejected by a real Wallet with a version-inference error ("Could not
        // infer openid4vp version..."). The correct prefix name, confirmed
        // against the published spec text, is `decentralized_identifier`
        // (example in §5.9.3: `"client_id":
        // "decentralized_identifier:did:example:123"`) — not `did`.
        // did:key needs no resolver call (the DID deterministically encodes the
        // public key), so a Wallet supporting the `decentralized_identifier`
        // Client Identifier Prefix and the did:key method can verify this Request
        // Object without any network lookup for the Verifier's key.
        //
        // IMPORTANT: `kid` in the signed JWT header and `client_id` must resolve
        // to the SAME DID — an earlier intermediate state during this debugging
        // session had client_id already switched to a new DID while the signing
        // call still used the old key/DID for `kid`, which is a guaranteed
        // verification failure (Wallet resolves the wrong key entirely). Both
        // GetVerifierClientId and SignRequestObjectES256 now derive from the same
        // GetVerifierDid (P-256) identity — keep it that way if this is touched
        // again.
        //
        // UNVERIFIED: this ES256/P-256 revert has not yet been re-tested against
        // a real Wallet as of this comment.
        // See OID4VP-1.0-COMPLIANCE-AUDIT.md finding H-01.
        [Route("request/{id}")]
        [HttpGet]
        public async Task<IActionResult> RequestURI(string id)
        {

            VCService vcServ = new VCService();
            DBService dbServ = new DBService();

            // FIX (M-05, 2026-08-09): this used to trust Request.Host directly. If
            // the Wallet's outbound call to /request/{id} arrives with a different
            // Host than what VerifierPresentVP used to build the client_id embedded
            // in the QR (e.g. via a misconfigured proxy or forwarded-header setup),
            // the client_id in this request object would silently disagree with the
            // one already handed to the Wallet — and, since Phase 1 items 6-8 now
            // actively check `aud` against session.ClientId, that mismatch would
            // start failing real presentations instead of just being a correctness
            // footgun. Now uses the same canonical INTERNAL_BASE_URL as
            // VerifierPresentVP so both places agree.
            // See OID4VP-1.0-COMPLIANCE-AUDIT.md finding M-05.
            var baseUrl = Environment.GetEnvironmentVariable("INTERNAL_BASE_URL")
              ?? $"{Request.Scheme}://{Request.Host}";
            string stateid = id;
            Dbdocumenttype docType =  dbServ.GetRequestDocType(id);
            if (docType == null)
            {
                return NotFound();
            }

            // FIX (C-03, 2026-08-08): this used to send `nonce = id` — the session
            // ID itself — instead of the random nonce actually stored for this
            // session, so the stored Nonce could never be used to validate what was
            // really sent to the Wallet. Now reads the real per-session nonce, and
            // persists the exact client_id issued here so the response (KB-JWT
            // `aud`, for SD-JWT VC) can be checked against it later.
            // See OID4VP-1.0-COMPLIANCE-AUDIT.md finding C-03 / C-02.
            VerifierDbContext context = new VerifierDbContext();
            var session = context.Dbverifiersessions.Where(s => s.Id == stateid).FirstOrDefault();
            if (session == null || session.ExpiresAt < DateTime.UtcNow)
            {
                return NotFound();
            }
            string nonce = session.Nonce;
            // FIX (H-01, 2026-08-10) — CORRECTED: client_id is now
            // `decentralized_identifier:did:key:...` — see this method's leading
            // comment for the correction from a bare (unprefixed) DID. response_uri
            // is still sent explicitly below since, unlike the redirect_uri Client
            // Identifier Prefix, a decentralized_identifier: client_id does not
            // implicitly carry it.
            string clientId = vcServ.GetVerifierClientId(_env);
            session.ClientId = clientId;

            // FIX (Phase 1 item 2, 2026-08-09): persist the exact DCQL query issued
            // for this session so VerifierVP can later check the returned credential
            // against what was actually requested, instead of trusting the Wallet's
            // response blindly. See OID4VP-1.0-COMPLIANCE-AUDIT.md Phase 1 item 2 / H-04.
            var dcqlQueryObj = vcServ.BuildDcqlQuery(docType, Request);
            session.DcqlQuery = JsonConvert.SerializeObject(dcqlQueryObj);
            context.SaveChanges();

            // FIX (H-03, 2026-08-09): see BuildClientMetadata above — SD-JWT formats
            // need sd-jwt_alg_values/kb-jwt_alg_values, not the generic alg_values
            // shape. See OID4VP-1.0-COMPLIANCE-AUDIT.md finding H-03.
            var clientMetadata = BuildClientMetadata(docType);

            var payloadObj = new
            {
                response_type = "vp_token",
                client_id = clientId,
                response_mode = "direct_post",
                state = stateid,
                dcql_query = dcqlQueryObj,
                client_metadata = clientMetadata,
                nonce = nonce,
                response_uri = $"{baseUrl}/openid4vc/verify/{stateid}"
            };

            // FIX (H-01, 2026-08-11) — SWITCHED BACK to ES256/P-256, per explicit
            // instruction: sign with the Verifier's ES256/P-256 did:key (kid =
            // did:key verificationMethod id) instead of the Ed25519 key used
            // briefly on 2026-08-10 — see this method's leading comment. Uses the
            // same GetVerifierDid (P-256) identity as GetVerifierClientId above
            // so kid and client_id agree on the same DID (a prior intermediate
            // state signed with a different key than client_id pointed at —
            // mismatched, and the direct cause of a "Error during verification of
            // jwt" failure; that bug is now fixed, but this ES256 revert has not
            // itself been re-tested live).
            // See OID4VP-1.0-COMPLIANCE-AUDIT.md finding H-01.
            var jwt = vcServ.SignRequestObjectES256(payloadObj, _env);

            return Content(jwt, "application/oauth-authz-req+jwt");

            //return Ok(new
            //{
            //    response_type = presentationOffer.response_type,
            //    client_id = $"redirect_uri:{presentationOffer.client_id}",
            //    response_mode = presentationOffer.response_mode,
            //    state = presentationOffer.state,
            //    dcql_query = BuildDcqlQuery(docType),
            //    client_metadata = clientMetadata,
            //    nonce = presentationOffer.nonce,
            //    response_uri = presentationOffer.response_uri
            //});


        }

        private static string Base64UrlEncode(string json)
        {
            return Convert.ToBase64String(Encoding.UTF8.GetBytes(json))
                .Replace("+", "-")
                .Replace("/", "_")
                .TrimEnd('=');
        }

        // NOTE (H-01): no /jwks endpoint exists here — the Verifier's ES256/P-256
        // key is verified via did:key (the DID self-encodes the public key, see
        // VCService.GetVerifierDid), so there's no JWKS to serve.

        [Route("verify/{id}")]
        [HttpPost]
        // FEATURE (audit trail, 2026-08-15): see VerifierAuditLogFilter for why
        // this is a post-action filter rather than instrumenting this method's
        // ~15 return points directly.
        [TypeFilter(typeof(VerifierAuditLogFilter))]
        public async Task<IActionResult> VerifierVP(
            [FromForm] string? vp_token,
            [FromForm] string state,
            // FIX (M-01, 2026-08-09): vp_token used to be a required (non-nullable)
            // parameter, so a legitimate Wallet Authorization Error Response
            // (error/error_description/state, no vp_token) failed ASP.NET's
            // automatic model-binding validation as a raw, unhelpful 400 before any
            // of this method's own code ever ran. vp_token is now optional and
            // error/error_description/error_uri are accepted and handled explicitly
            // below. See OID4VP-1.0-COMPLIANCE-AUDIT.md finding M-01.
            [FromForm] string? error = null,
            [FromForm] string? error_description = null,
            [FromForm] string? error_uri = null,
            // FIX (H-01 follow-up / NFC-mdoc support, 2026-08-11): standard
            // OpenID4VP direct_post has no slot for the ISO 18013-5 proximity
            // engagement material (DeviceEngagement/EReaderKey/NFC Handover)
            // that MdocService.VerifyMdocPresentation needs to reconstruct the
            // real SessionTranscript for a genuine NFC proximity session — these
            // are deployment-specific extra form fields the reader app backend
            // must submit alongside vp_token, base64url-encoded, whenever
            // vp_token is an mso_mdoc DeviceResponse. Not used by any other
            // format. See OID4VP-1.0-COMPLIANCE-AUDIT.md finding H-01.
            [FromForm] string? device_engagement = null,
            [FromForm] string? e_reader_key = null,
            [FromForm] string? handover_select = null,
            [FromForm] string? handover_request = null)//[FromForm] string presentation_submission,)
        {

            VCService vpServ = new VCService();
            string vc_token = null;
            string vctoken = null;
            string vcResult = null;
            string vp_payload = null;
            string stateid = null;
            string details = null;
            string vpTokenForResolve = null;

            // SECURITY (session consumption + C-02/C-03 dependency, 2026-08-08): look
            // up and validate the session up front, before any cryptographic work, so
            // an unknown/expired/already-consumed session is rejected immediately, and
            // so session.Nonce / session.ClientId are available for the SD-JWT KB-JWT
            // nonce/aud check below. See OID4VP-1.0-COMPLIANCE-AUDIT.md C-02 / H-07.
            VerifierDbContext context;
            Dbverifiersession session;
            try
            {
                context = new VerifierDbContext();
                session = context.Dbverifiersessions.Where(s => s.Id == state).FirstOrDefault();
            }
            catch (Exception)
            {
                return BadRequest(new
                {
                    error = "invalid_request context",
                    error_description = "Present VP is invalid"
                });
            }
            if (session == null)
            {
                return BadRequest(new
                {
                    error = "invalid_request session",
                    error_description = "Unknown session"
                });
            }
            if (session.ExpiresAt < DateTime.UtcNow)
            {
                return BadRequest(new
                {
                    error = "invalid_request expire",
                    error_description = "Session has expired"
                });
            }
            if (string.Equals(session.Status, "Consumed", StringComparison.OrdinalIgnoreCase))
            {
                logger.Info("Rejected: session already consumed (replay attempt)");
                return BadRequest(new
                {
                    error = "invalid_request reject",
                    error_description = "This session has already been used"
                });
            }

            // FIX (M-04 remediation, 2026-08-23): every verify-failure return point in
            // this method used to leave the session sitting at "Pending" forever (until
            // its 10-minute expiry) — only this Wallet-error-response path (just below)
            // ever set session.Status = "Failed". A presentation that failed
            // cryptographic/DCQL verification (bad signature, wrong credential,
            // nonce/aud mismatch, etc.) was therefore indistinguishable from "Wallet
            // hasn't responded yet" to a caller polling status: GetScanStatus
            // (VerifierScanController) infers status purely from whether a
            // Dbverifierresponse row exists, and no row is ever written for a failed
            // verification. Centralizing "mark this session Failed, then return the
            // failure body" here means every one of this method's ~15 failure returns
            // does it consistently, instead of repeating the
            // set-fields/try/SaveChanges/catch block at each site (or, as before,
            // omitting it entirely everywhere except this one path).
            // See OID4VP-1.0-COMPLIANCE-AUDIT.md finding M-04.
            IActionResult FailSession(object body)
            {
                try
                {
                    session.Status = "Failed";
                    session.CompletedAt = DateTime.UtcNow;
                    context.SaveChanges();
                }
                catch (Exception)
                {
                    // best-effort — still return the failure body below even if this
                    // write fails.
                }
                return BadRequest(body);
            }

            // FIX (M-01, 2026-08-09): a Wallet Authorization Error Response — the
            // Wallet declining/failing the request — is a normal, spec-defined
            // outcome, not a malformed request. Record it against the session (as
            // Failed, distinct from a successful Consumed) instead of leaving the
            // session dangling as Pending until it expires, and report the Wallet's
            // own error code back rather than a generic invalid_request.
            // See OID4VP-1.0-COMPLIANCE-AUDIT.md finding M-01.
            if (!string.IsNullOrEmpty(error))
            {
                logger.Info($"Wallet returned an Authorization Error Response: {error}");
                return FailSession(new
                {
                    error,
                    error_description = error_description ?? "Wallet returned an authorization error"
                });
            }

            if (string.IsNullOrEmpty(vp_token))
            {
                return FailSession(new
                {
                    error = "invalid_request",
                    error_description = "Missing vp_token"
                });
            }

            // FIX (Phase 1 item 6 / H-05, 2026-08-09): look up this session's
            // configured AlgValues so the credential's signature algorithm can be
            // checked against what's actually permitted for its format/query,
            // instead of silently accepting whatever alg the token declares.
            // See OID4VP-1.0-COMPLIANCE-AUDIT.md Phase 1 item 6 / H-05.
            string[] permittedAlgs = null;
            // FIX (H-01 follow-up / NFC-mdoc support, 2026-08-11): hoisted out of
            // the try block below so it's also available to route mso_mdoc
            // presentations to MdocService instead of the JWT/SD-JWT logic
            // further down. See OID4VP-1.0-COMPLIANCE-AUDIT.md finding H-01.
            Dbdocumenttype docTypeForAlg = null;
            try
            {
                docTypeForAlg = context.Dbdocumenttypes.Where(d => d.TypeId == session.DocTypeId).FirstOrDefault();
                if (!string.IsNullOrEmpty(docTypeForAlg?.AlgValues))
                {
                    permittedAlgs = JsonConvert.DeserializeObject<string[]>(docTypeForAlg.AlgValues);
                }
            }
            catch (Exception)
            {
                permittedAlgs = null; // fail open on lookup errors — VerifyJWS treats null as "no restriction"
            }

            try
            {

                logger.Info("VerifierVP: request received");

                // FIX (C-01, 2026-08-09): the final OpenID4VP 1.0 vp_token shape
                // (§8) for a DCQL response is a JSON object mapping each DCQL
                // credential query id to an array of credential strings, e.g.
                // {"transcript_credential": ["<jwt-or-sd-jwt>"]} — not a bare JWS
                // string or a legacy bare JSON array. A conforming Wallet's response
                // could not be parsed before this. Uses the DCQL query id stored on
                // the session (Phase 1 item 2) to pick the right entry when present;
                // falls back to the first property otherwise. The legacy bare-array
                // and bare-JWS shapes below are still accepted for now so older
                // Wallet builds in the current test environment keep working.
                // See OID4VP-1.0-COMPLIANCE-AUDIT.md finding C-01.
                if (!string.IsNullOrEmpty(vp_token) && vp_token.TrimStart().StartsWith("{"))
                {
                    try
                    {
                        using var vpTokenDoc = System.Text.Json.JsonDocument.Parse(vp_token);
                        System.Text.Json.JsonElement root = vpTokenDoc.RootElement;

                        string credentialQueryId = null;
                        try
                        {
                            if (!string.IsNullOrEmpty(session.DcqlQuery))
                            {
                                using var dcqlDoc = System.Text.Json.JsonDocument.Parse(session.DcqlQuery);
                                if (dcqlDoc.RootElement.TryGetProperty("credentials", out var credsEl) && credsEl.GetArrayLength() > 0)
                                {
                                    var firstCred = credsEl.EnumerateArray().First();
                                    if (firstCred.TryGetProperty("id", out var idEl))
                                        credentialQueryId = idEl.GetString();
                                }
                            }
                        }
                        catch
                        {
                            credentialQueryId = null; // fall back to first-property below
                        }

                        System.Text.Json.JsonElement? matchedArray = null;
                        if (!string.IsNullOrEmpty(credentialQueryId) && root.TryGetProperty(credentialQueryId, out var exact))
                        {
                            matchedArray = exact;
                        }
                        else
                        {
                            foreach (var prop in root.EnumerateObject())
                            {
                                matchedArray = prop.Value;
                                break;
                            }
                        }

                        if (matchedArray is System.Text.Json.JsonElement arrEl &&
                            arrEl.ValueKind == System.Text.Json.JsonValueKind.Array &&
                            arrEl.GetArrayLength() > 0)
                        {
                            var first = arrEl.EnumerateArray().First();
                            if (first.ValueKind == System.Text.Json.JsonValueKind.String)
                            {
                                vp_token = first.GetString();
                                logger.Info("vp_token extracted from final OpenID4VP JSON object shape");
                            }
                        }
                    }
                    catch
                    {
                        logger.Info("vp_token JSON object parse failed");
                    }
                }
                // Legacy bare JSON array shape (pre-final draft) — kept for backward
                // compatibility alongside the final shape above.
                else if (!string.IsNullOrEmpty(vp_token) && vp_token.TrimStart().StartsWith("["))
                {
                    try
                    {
                        var arr = System.Text.Json.JsonSerializer.Deserialize<string[]>(vp_token);
                        vp_token = arr?.FirstOrDefault() ?? vp_token;
                        logger.Info("vp_token extracted from array");
                    }
                    catch
                    {
                        logger.Info("vp_token JSON parse failed");
                    }
                }

                vpTokenForResolve = vp_token?.Trim();

                // FIX (H-01 follow-up / NFC-mdoc support, 2026-08-11): mso_mdoc
                // credentials (ISO 18013-5 DeviceResponse, base64url-encoded CBOR
                // per OpenID4VP Appendix B.2) are a completely different encoding
                // from the JWT/SD-JWT paths below (CBOR/COSE_Sign1, not JWS) —
                // route to the dedicated CBOR/COSE verifier (MdocService) instead
                // of treating vpTokenForResolve as a JWS. Routed by this
                // session's configured document type/format (persisted on the
                // session at RequestURI time) rather than by sniffing the token
                // shape, since a bare base64url string gives no reliable signal
                // on its own. The rest of this try block (the existing
                // JWT/SD-JWT logic, wrapped in the `else` below) is skipped
                // entirely for mso_mdoc — this branch is intentionally
                // self-contained rather than reusing/restructuring that existing
                // logic, to avoid risking the working JWT/SD-JWT path. Indentation
                // of the untouched JWT/SD-JWT block below was NOT renormalized
                // after wrapping it in this `else`, to keep this diff minimal and
                // reviewable.
                //
                // UNVERIFIED: this mdoc path has not been tested against a real
                // Wallet/NFC device — see MdocService.cs for caveats.
                // See OID4VP-1.0-COMPLIANCE-AUDIT.md finding H-01.
                bool isMsoMdoc = string.Equals(docTypeForAlg?.Format, "mso_mdoc", StringComparison.OrdinalIgnoreCase);
                if (isMsoMdoc)
                {
                    string mdocResponseUri = (Environment.GetEnvironmentVariable("INTERNAL_BASE_URL")
                        ?? $"{Request.Scheme}://{Request.Host}") + $"/openid4vc/verify/{state}";

                    // FIX (H-01 follow-up / NFC-mdoc support, 2026-08-11): this
                    // deployment's reader app does a real NFC proximity
                    // DeviceEngagement/EReaderKey handshake with the wallet, not
                    // a purely remote OpenID4VP exchange — decode the raw
                    // engagement/handover bytes it forwarded so
                    // VerifyMdocPresentation builds the correct (proximity, not
                    // redirect-invocation) SessionTranscript. See
                    // MdocService.BuildProximitySessionTranscript.
                    byte[]? deviceEngagementBytes = null;
                    byte[]? eReaderKeyBytes = null;
                    byte[]? handoverSelectBytes = null;
                    byte[]? handoverRequestBytes = null;
                    try
                    {
                        if (!string.IsNullOrEmpty(device_engagement)) deviceEngagementBytes = vpServ.Base64UrlDecode(device_engagement);
                        if (!string.IsNullOrEmpty(e_reader_key)) eReaderKeyBytes = vpServ.Base64UrlDecode(e_reader_key);
                        if (!string.IsNullOrEmpty(handover_select)) handoverSelectBytes = vpServ.Base64UrlDecode(handover_select);
                        if (!string.IsNullOrEmpty(handover_request)) handoverRequestBytes = vpServ.Base64UrlDecode(handover_request);
                    }
                    catch (Exception e)
                    {
                        logger.Info($"mdoc engagement fields failed to base64url-decode: {e.Message}");
                        return FailSession(new
                        {
                            error = "invalid_request",
                            error_description = "Present VP is invalid",
                            reason = "malformed_engagement_bytes"
                        });
                    }
                    if (deviceEngagementBytes == null || eReaderKeyBytes == null || handoverSelectBytes == null)
                    {
                        logger.Info("mdoc verify failed: device_engagement/e_reader_key/handover_select missing");
                        return FailSession(new
                        {
                            error = "invalid_request",
                            error_description = "Present VP is invalid",
                            reason = "missing_engagement_bytes"
                        });
                    }

                    var mdocResult = new MdocService().VerifyMdocPresentation(
                        vpTokenForResolve,
                        session.ClientId,
                        session.Nonce,
                        mdocResponseUri,
                        vpServ,
                        deviceEngagementBytes,
                        eReaderKeyBytes,
                        handoverSelectBytes,
                        handoverRequestBytes);

                    if (!mdocResult.IsValid)
                    {
                        logger.Info($"mdoc verify failed: {mdocResult.ErrorCode} — {mdocResult.ErrorMessage}");
                        return FailSession(new
                        {
                            error = "invalid_request verify failed",
                            error_description = "Present VP is invalid",
                            reason = mdocResult.ErrorCode
                        });
                    }

                    if (!vpServ.ValidateAgainstDcqlQuery(session.DcqlQuery, "mso_mdoc", mdocResult.DocType, out string mdocDcqlErr))
                    {
                        logger.Info($"mdoc DCQL result check failed: {mdocDcqlErr}");
                        return FailSession(new
                        {
                            error = "invalid_request mdoc DCQL result check failed",
                            error_description = "Present VP is invalid",
                            reason = mdocDcqlErr
                        });
                    }

                    vc_token = vp_token?.Trim(); // raw base64url DeviceResponse, stored as-is
                    vp_payload = null; // no JWT payload segment for mdoc — nothing to persist here
                    logger.Info("mdoc verify passed (IssuerAuth + digests + DeviceAuth verified)");
                }
                else
                {
                if (vpTokenForResolve != null && vpTokenForResolve.Contains('~'))
                {
                    vpTokenForResolve = vpTokenForResolve.Split('~')[0];
                    logger.Info("SD-JWT detected, using JWT part");
                }
                JWSModel jwsModel = vpServ.ResolvePublicKey(vpTokenForResolve);
                jwsModel.vptoken = vpTokenForResolve;
                string didkey = jwsModel.didkey;


                if (string.IsNullOrEmpty(didkey))
                {
                    return FailSession(new
                    {
                        error = "invalid_request sd-jwt",
                        error_description = "Present VP is invalid"
                    });
                }


                // logs.Add(JsonSerializer.Serialize("=>> " + didkey, new JsonSerializerOptions { WriteIndented = true }));

                Task<string> x = vpServ.ResolveDID(didkey, jwsModel.kidFull);
                logger.Info("Resolving VP signer DID");
                if (vpServ.VerifyJWS(vpTokenForResolve?.Trim(), x.Result, out string ErrMsg))
                {
                    //logs.Add(JsonSerializer.Serialize("Start Verify VC", new JsonSerializerOptions { WriteIndented = true }));

                    //verify vc
                    JWSModel vcModel = vpServ.ResolvePublicKey(vpTokenForResolve?.Trim());
                    vp_payload = vcModel.payload;
                    stateid = vpServ.ResolveStateID(vcModel.payload);
                    vctoken = vpServ.VerifyVCToken(vcModel.payload);

                    // ✅ ถ้า vctoken เป็น null แสดงว่าเป็น dc+sd-jwt
                    // vp_token คือ VC โดยตรง
                    if (string.IsNullOrEmpty(vctoken))
                    {
                        vctoken = vp_token?.Trim(); // SD-JWT เต็มชุด
                        logger.Info("dc+sd-jwt format: using vp_token as vctoken directly");
                    }

                    // ตรวจสอบว่าเป็น SD-JWT หรือไม่
                    bool isSdJwt = vctoken != null && vctoken.Contains('~');

                    // ✅ ตัดเฉพาะ JWT ส่วนแรก (ไม่เอา disclosures และ KB-JWT)
                    string jwtForVerify = isSdJwt ? vctoken.Split('~')[0] : vctoken;

                    vcModel = vpServ.ResolvePublicKey(jwtForVerify);
                    string issuer_did = vcModel.didkey;
                    //logs.Add(JsonSerializer.Serialize("vc token => " + vctoken, new JsonSerializerOptions { WriteIndented = true }));
                    issuer_did = vcModel.didkey;


                    Task<string> vc_x = vpServ.ResolveDID(issuer_did, vcModel.kidFull);
                    logger.Info($"issuer_did => {issuer_did}");
                    //check vc jws

                    if (isSdJwt)
                    {
                        // SECURITY (C-04 remediation, 2026-08-08): full SD-JWT VC
                        // verification — disclosure digests, KB-JWT signature against
                        // the holder key declared in `cnf`, sd_hash, and KB-JWT
                        // nonce/aud/iat against this session. Replaces the Phase 0
                        // hard-reject of dc+sd-jwt now that this exists.
                        // See OID4VP-1.0-COMPLIANCE-AUDIT.md finding C-04.
                        var sdResult = vpServ.VerifySDJWTPresentation(
                            vctoken,
                            vc_x.Result,
                            session.Nonce,
                            session.ClientId,
                            permittedAlgs);

                        if (!sdResult.IsValid)
                        {
                            logger.Info($"SD-JWT verify failed: {sdResult.ErrorCode} — {sdResult.ErrorMessage}");
                            return FailSession(new
                            {
                                error = "invalid_request verify failed",
                                error_description = "Present VP is invalid",
                                reason = sdResult.ErrorCode
                            });
                        }

                        // FIX (Phase 1 item 8 / H-04, 2026-08-09): confirm the returned
                        // credential's vct matches what this session's DCQL query
                        // actually asked for, instead of accepting whatever vct the
                        // Wallet sent and only using it to pick a display route.
                        // See OID4VP-1.0-COMPLIANCE-AUDIT.md Phase 1 item 8 / H-04.
                        string actualVct = vpServ.GetVctFromSdJwt(vctoken);
                        if (!vpServ.ValidateAgainstDcqlQuery(session.DcqlQuery, "dc+sd-jwt", actualVct, out string sdDcqlErr))
                        {
                            logger.Info($"SD-JWT DCQL result check failed: {sdDcqlErr}");
                            return FailSession(new
                            {
                                error = "invalid_request SD-JWT DCQL result check failed",
                                error_description = "Present VP is invalid",
                                reason = sdDcqlErr
                            });
                        }

                        vc_token = vp_token?.Trim(); // เก็บ VC เต็ม (รวม ~ disclosures + KB-JWT)
                        logger.Info("SD-JWT VC verify passed (disclosures + KB-JWT + nonce/aud verified)");
                    }
                    else if (vpServ.VerifyJWS(jwtForVerify, vc_x.Result, out ErrMsg, permittedAlgs))
                    {
                        //vcModel = vpServ.ResolvePublicKey(vctoken);
                        //byte[] vcDecode = vpServ.Base64UrlDecode(vcModel.payload);
                        //vcResult = Encoding.UTF8.GetString(vcDecode);
                        //vc_token = vcModel.payload;

                        // FIX (Phase 1 item 7 / C-02, 2026-08-09): the outer VP-JWT's
                        // own nonce/aud must match this session — previously never
                        // checked for jwt_vc_json (only the SD-JWT KB-JWT path had an
                        // equivalent check). See OID4VP-1.0-COMPLIANCE-AUDIT.md
                        // Phase 1 item 7 / C-02.
                        if (!vpServ.ValidateVpNonceAndAudience(vp_payload, session.Nonce, session.ClientId, out string nonceAudErr))
                        {
                            logger.Info($"jwt_vc_json VP nonce/aud check failed: {nonceAudErr}");
                            return FailSession(new
                            {
                                error = "invalid_request jwt_vc_json VP nonce/aud check failed",
                                error_description = "Present VP is invalid",
                                reason = nonceAudErr
                            });
                        }

                        vcModel = vpServ.ResolvePublicKey(jwtForVerify);
                        byte[] vcDecode = vpServ.Base64UrlDecode(vcModel.payload);
                        vcResult = Encoding.UTF8.GetString(vcDecode);
                        vc_token = vp_token?.Trim(); // เก็บ VC เต็ม (รวม ~ disclosures ถ้าเป็น SD-JWT)
                        logger.Info($"VC verify passed, isSdJwt={isSdJwt}");

                        // FIX (Phase 1 item 8 / H-04, 2026-08-09): credential time
                        // validity (nbf/exp) + confirm the returned credential's type
                        // matches what this session's DCQL query asked for. Parse
                        // failures here fall through and let the existing (pre-item-8)
                        // flow continue rather than newly hard-failing on a shape this
                        // wasn't written to anticipate.
                        // See OID4VP-1.0-COMPLIANCE-AUDIT.md Phase 1 item 8 / H-04.
                        try
                        {
                            using JsonDocument vcDoc = JsonDocument.Parse(vcResult);
                            long? credNbf = vcDoc.RootElement.TryGetProperty("nbf", out var nbfEl) && nbfEl.TryGetInt64(out long nbfVal) ? nbfVal : (long?)null;
                            long? credExp = vcDoc.RootElement.TryGetProperty("exp", out var expEl) && expEl.TryGetInt64(out long expVal) ? expVal : (long?)null;
                            if (!vpServ.IsCredentialTimeValid(credNbf, credExp, out string timeErr))
                            {
                                logger.Info($"jwt_vc_json time validity check failed: {timeErr}");
                                return FailSession(new
                                {
                                    error = $"invalid_request jwt_vc_json time validity check failed: {timeErr}",
                                    error_description = "Present VP is invalid",
                                    reason = timeErr
                                });
                            }

                            string actualType = null;
                            if (vcDoc.RootElement.TryGetProperty("vc", out var vcEl) &&
                                vcEl.TryGetProperty("type", out var typeEl) && typeEl.ValueKind == JsonValueKind.Array)
                            {
                                actualType = typeEl.EnumerateArray()
                                    .Select(t => t.ValueKind == JsonValueKind.String ? t.GetString() : null)
                                    .Where(t => t != null)
                                    .LastOrDefault();
                            }
                            if (!vpServ.ValidateAgainstDcqlQuery(session.DcqlQuery, "jwt_vc_json", actualType, out string jwtDcqlErr))
                            {
                                logger.Info($"jwt_vc_json DCQL result check failed: {jwtDcqlErr}");
                                return FailSession(new
                                {
                                    error = $"invalid_request jwt_vc_json DCQL result check failed: {jwtDcqlErr}",
                                    error_description = "Present VP is invalid",
                                    reason = jwtDcqlErr
                                });
                            }
                        }
                        catch (System.Text.Json.JsonException)
                        {
                            // A JWT payload is JSON by definition, so if this segment
                            // doesn't parse, the credential is malformed/corrupted —
                            // not just "an unexpected but valid shape" (those are
                            // handled above via TryGetProperty without throwing).
                            // Reject rather than silently skip time/DCQL validation.
                            logger.Info("jwt_vc_json VC payload was not valid JSON");
                            return FailSession(new
                            {
                                error = "invalid_request jwt_vc_json VC payload was not valid JSON",
                                error_description = "Present VP is invalid",
                                reason = "malformed_vc_payload"
                            });
                        }

                        //decodeURIComponent()
                        //**var data = Json(vcResult);
                        //logs.Add(JsonSerializer.Serialize(request, new JsonSerializerOptions { WriteIndented = true }));
                        // logs.Add(JsonSerializer.Serialize("========= Result VC ==========", new JsonSerializerOptions { WriteIndented = true }));
                        //logs.Add(JsonSerializer.Serialize(vcResult, new JsonSerializerOptions { WriteIndented = true }));
                    }
                    else
                    {
                        // FIX (M-04, 2026-08-08): previously fell through and still
                        // wrote a "successful" response row / returned 200 even though
                        // the VC signature never verified, which made GetScanStatus
                        // report "completed" for a credential that failed verification.
                        logger.Info($"VC verify failed: {ErrMsg}");
                        return FailSession(new
                        {
                            error = $"invalid_request VC verify failed: {ErrMsg}",
                            error_description = "Present VP is invalid"
                        });
                    }

                }
                else
                {
                    // FIX (silent-failure diagnosability, 2026-08-21): this branch used to
                    // return a hardcoded "invalid_request **** " placeholder and never log
                    // anything — a real failure here (e.g. DID resolution returning no/wrong
                    // key, wrong alg, corrupted signature) was completely opaque: the app log
                    // showed "Resolving VP signer DID" and then nothing, straight to the 400,
                    // with no way to tell why. VerifyJWS's actual ErrMsg was computed but
                    // discarded. Now logged and returned like every other verify-failure path
                    // below (e.g. the VC-verify-failed branch a few lines down).
                    logger.Info($"Outer VP JWS verify failed: {ErrMsg}");
                    return FailSession(new
                    {
                        error = $"invalid_request VP verify failed: {ErrMsg}",
                        error_description = "Present VP is invalid",
                        reason = "vp_signature_invalid"
                    });
                }
                } // closes `else` for `if (isMsoMdoc)` added above (H-01 follow-up / NFC-mdoc support)

            }
            catch (Exception e)
            {
                // FIX (M-04 remediation, 2026-08-23): an unhandled exception anywhere in
                // the verification try block above is a failure just like any of the
                // explicit checks — previously this left the session Pending too.
                return FailSession(new
                {
                    error = $"invalid_request {e.Message}",
                    error_description = "Present VP is invalid"
                });
            }

            string baseUrl = null;
            try
            {

                //string url = vpServ.CheckHttps(HttpContext.Request.GetDisplayUrl());
                string vct = vpServ.GetVctFromSdJwt(vpTokenForResolve);
                logger.Info($"vct => {vct}");
                string docType = vct switch
                {
                    string v when v.EndsWith("TranscriptCredential") => "TranscriptCredential_dc+sd-jwt",
                    string v when v.EndsWith("Iso18013DriversLicenseCredential") => "Iso18013DriversLicenseCredential_dc+sd-jwt",
                    string v when v.EndsWith("IDCard") => "IDCard_dc+sd-jwt",
                    _ => null
                };

                string url = HttpContext.Request.IsHttps ? "https://" : "http://";
                var externalBase = Environment.GetEnvironmentVariable("BASE_URL") ?? $"{url}{Request.Host}";

                // FIX (M-02, 2026-08-09): redirect_uri used to embed `state`, which
                // was already disclosed to the Wallet earlier in this same exchange
                // — anyone who observed it (browser history, referrer, shared device)
                // could fetch the result for as long as the row existed, with no
                // expiry. ResponseCode previously just stored the literal string
                // "200" (an HTTP status, not a secret) and was never freshly
                // generated. It's repurposed here as an actual random, single-use-
                // window response code: freshly generated on every response, and
                // PresentResultController now looks results up by this code (with a
                // short validity window) instead of by SessionId.
                // See OID4VP-1.0-COMPLIANCE-AUDIT.md finding M-02.
                string responseCode = WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32));

                baseUrl = $"{externalBase}/PresentResult/Result/{responseCode}";
                logger.Info($"result => {docType}");

                //save to result to db
                Dbverifierresponse dbresult = new Dbverifierresponse();

                //dbresult.Id = vpServ.GetGUID();
                dbresult.SessionId = state;
                dbresult.VpToken = vp_payload;
                dbresult.VcPayload = vc_token;// vctoken;
                dbresult.PresentationSubmission = null;
                dbresult.ResponseCode = responseCode;
                dbresult.ReceivedAt = DateTime.UtcNow;

                var oldResult = context.Dbverifierresponses.Where(i => i.SessionId == state).FirstOrDefault();
                if (oldResult != null)
                {
                    //update
                    //oldResult.SessionId = stateid;
                    oldResult.VpToken = vp_payload;
                    oldResult.VcPayload = vc_token;
                    oldResult.ResponseCode = responseCode;
                    oldResult.ReceivedAt = DateTime.UtcNow;
                }
                else
                {
                    //new
                    context.Dbverifierresponses.Add(dbresult);
                }

                // mark the session consumed in the same SaveChanges (single DB
                // transaction) as the response write, so a session can't be read as
                // "still open" between the two writes.
                session.Status = "Consumed";
                session.CompletedAt = DateTime.UtcNow;

                context.SaveChanges();
            }
            catch (Exception e)
            {
                return BadRequest(new
                {
                    error = $"invalid_request {e.Message}",
                    error_description = "Present VP is invalid"
                });
            }


            //logs.Add(JsonSerializer.Serialize("Present VP Success", new JsonSerializerOptions { WriteIndented = true }));
            // return Content(baseUrl);
            return Ok(new
            {
                redirect_uri = baseUrl
            });

        }


        // SECURITY (Phase 0 remediation, 2026-08-08): this endpoint returned the raw
        // VP token and VC payload for any supplied session ID with no authorization
        // check, disclosing identity data to anyone who obtained or guessed a
        // session ID. Disabled until authenticated/authorized access and
        // minimum-necessary claim disclosure are implemented. See
        // OID4VP-1.0-COMPLIANCE-AUDIT.md finding H-08.
        [Route("vp/{id}")]
        [HttpGet]
        [Tags("Verifier")]
        public IActionResult GetVP(string id)
        {
            return StatusCode(410, new
            {
                error = "endpoint_disabled",
                error_description = "This endpoint has been disabled pending authorization controls (see H-08 in the compliance audit)."
            });
#pragma warning disable CS0162
            try
            {
                if (string.IsNullOrWhiteSpace(id))
                    return BadRequest(new { error = "id is required" });

                VerifierDbContext context = new VerifierDbContext();
                var result = context.Dbverifierresponses
                    .Where(r => r.SessionId == id)
                    .FirstOrDefault();

                if (result == null)
                    return NotFound(new { error = $"ไม่พบ session '{id}'" });

                return Ok(new
                {
                    sessionId = result.SessionId,
                    vpToken = result.VpToken,
                    vcPayload = result.VcPayload,
                    receivedAt = result.ReceivedAt,
                    responseCode = result.ResponseCode
                });
            }
            catch (Exception ex)
            {
                logger.Error($"GetVP error: {ex.Message}");
                return StatusCode(500, new { error = ex.Message });
            }
#pragma warning restore CS0162
        }

        // FIX (M-03, 2026-08-09): removed a second, commented-out (non-compiled)
        // implementation of GET /verifier/status/{sessionId} that duplicated
        // VerifierScanController.GetScanStatus, the one actually live route for
        // status polling. Kept ParseClaimsFromVcPayload below since it's a working,
        // safe SD-JWT-aware claims decoder that's a reasonable starting point for
        // the "return minimum necessary claims" part of H-08, even though nothing
        // currently calls it. See OID4VP-1.0-COMPLIANCE-AUDIT.md finding M-03.
        private static Dictionary<string, object> ParseClaimsFromVcPayload(string? vcPayload)
        {
            if (string.IsNullOrWhiteSpace(vcPayload))
                return new Dictionary<string, object>();

            // ---- กรณี SD-JWT: <Issuer-signed JWT>~<disclosure1>~<disclosure2>~...~[KB-JWT] ----
            if (vcPayload.Contains('~'))
            {
                var claims = new Dictionary<string, object>();
                var parts = vcPayload.Split('~', StringSplitOptions.RemoveEmptyEntries);

                // parts[0] คือ issuer-signed JWT (header.payload.sig) — ข้าม ไม่ใช่ disclosure
                for (int i = 1; i < parts.Length; i++)
                {
                    try
                    {
                        var decoded = Base64UrlDecodeToString(parts[i]);
                        var arr = JsonConvert.DeserializeObject<JArray>(decoded);

                        // disclosure ของ object property มาตรฐาน = [salt, claimName, claimValue]
                        if (arr != null && arr.Count == 3)
                        {
                            var claimName = arr[1].ToString();
                            var valueToken = arr[2];
                            claims[claimName] = valueToken.Type == JTokenType.Object || valueToken.Type == JTokenType.Array
                                ? valueToken.ToString(Formatting.None)
                                : valueToken.ToObject<object>();
                        }
                        // ถ้า parts[i] ไม่ใช่ disclosure ที่ decode ออกมาเป็น array 3 ตัว มักเป็น
                        // Key Binding JWT ที่แปะท้ายสุด (มีจุด . คั่น ไม่ใช่ base64url ของ JSON array
                        // เฉย ๆ) — ข้ามเงียบ ๆ ไม่ถือเป็น error
                    }
                    catch
                    {
                        // decode/parse ไม่ออก (เช่นเจอ KB-JWT) ข้ามไปตัวถัดไป
                    }
                }

                if (claims.Count > 0)
                    return claims;
                // ถ้า decode disclosure ไม่ได้เลยสักตัว ให้ตกไป fallback ด้านล่าง
            }

            // ---- fallback: เผื่อ VcPayload เป็น JSON object claims ตรง ๆ (ไม่ใช่ SD-JWT) ----
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

        private static string Base64UrlDecodeToString(string input)
        {
            string s = input.Replace('-', '+').Replace('_', '/');
            switch (s.Length % 4)
            {
                case 2: s += "=="; break;
                case 3: s += "="; break;
            }
            var bytes = Convert.FromBase64String(s);
            return Encoding.UTF8.GetString(bytes);
        }
        // FIX (M-08, 2026-08-09): removed VerifierVP_old, a fully commented-out
        // (non-compiled) earlier version of VerifierVP, superseded by the active
        // implementation above. See OID4VP-1.0-COMPLIANCE-AUDIT.md finding M-08.
    }
 
}
