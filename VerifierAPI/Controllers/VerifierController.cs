using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using NLog;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Utilities;
using System;
using System.Net;
using System.Text;
using System.Text.Json;
using VerifierAPI.Databases;
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
            

        public VerifierController(ILogger<VerifierController> logger)
        {
            _logger = logger;
        }

        // FIX (M-08, 2026-08-09): removed a commented-out earlier version of
        // VerifierPresentVP (superseded by the active version below, which adds
        // URL-encoding and the same-device deeplink). See M-08 in the audit.

        [Route("/generate-vp-qr")]
        [HttpPost]
        public IActionResult VerifierPresentVP([FromBody] GenerateVpQrRequest docType)
        {
            VCService vcServ = new VCService();
            DBService dbServ = new DBService();
            VpRequestSession model = new VpRequestSession();

            baseUrl = Environment.GetEnvironmentVariable("INTERNAL_BASE_URL")
              ?? $"{Request.Scheme}://{Request.Host}";
            model = dbServ.SaveVerifierSession(docType.DocumentType.ToString());
            string nonce = model.nonce;
            string stateid = model.stateId;

            string request_uri = $"{baseUrl}/openid4vc/request/{stateid}";
            string clientId = $"redirect_uri:{baseUrl}/openid4vc/verify/{stateid}";

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

        // FIX (M-08, 2026-08-09): removed three unused private methods
        // (BuildDcqlQuery(DocumentType), BuildPresentationDefinition(Dbdocumenttype),
        // BuildDcqlQuery(string)) — none were called anywhere; the active DCQL
        // builder is VCService.BuildDcqlQuery(Dbdocumenttype, HttpRequest), used
        // below in RequestURI. See OID4VP-1.0-COMPLIANCE-AUDIT.md finding M-08.

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
            string clientId = $"redirect_uri:{baseUrl}/openid4vc/verify/{stateid}";
            session.ClientId = clientId;

            // FIX (Phase 1 item 2, 2026-08-09): persist the exact DCQL query issued
            // for this session so VerifierVP can later check the returned credential
            // against what was actually requested, instead of trusting the Wallet's
            // response blindly. See OID4VP-1.0-COMPLIANCE-AUDIT.md Phase 1 item 2 / H-04.
            var dcqlQueryObj = vcServ.BuildDcqlQuery(docType, Request);
            session.DcqlQuery = JsonConvert.SerializeObject(dcqlQueryObj);
            context.SaveChanges();

            // Build client_metadata จาก DB
            var algValues = JsonConvert.DeserializeObject<string[]>(docType.AlgValues);
            var clientMetadata = new
            {
                vp_formats_supported = new Dictionary<string, object>
                {
                    [docType.Format] = new { alg_values = algValues }
                }
            };

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

            // แปลงเป็น Unsecured JWT (alg: none)
            var header = Base64UrlEncode("""{"alg":"none","typ":"oauth-authz-req+jwt"}""");
            var payload = Base64UrlEncode(JsonConvert.SerializeObject(payloadObj));
            var jwt = $"{header}.{payload}.";

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


        [Route("verify/{id}")]
        [HttpPost]
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
            [FromForm] string? error_uri = null)//[FromForm] string presentation_submission,)
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
                    error = "invalid_request",
                    error_description = "Present VP is invalid"
                });
            }
            if (session == null)
            {
                return BadRequest(new
                {
                    error = "invalid_request",
                    error_description = "Unknown session"
                });
            }
            if (session.ExpiresAt < DateTime.UtcNow)
            {
                return BadRequest(new
                {
                    error = "invalid_request",
                    error_description = "Session has expired"
                });
            }
            if (string.Equals(session.Status, "Consumed", StringComparison.OrdinalIgnoreCase))
            {
                logger.Info("Rejected: session already consumed (replay attempt)");
                return BadRequest(new
                {
                    error = "invalid_request",
                    error_description = "This session has already been used"
                });
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
                try
                {
                    session.Status = "Failed";
                    session.CompletedAt = DateTime.UtcNow;
                    context.SaveChanges();
                }
                catch (Exception)
                {
                    // best-effort — still report the Wallet's error below even if
                    // this write fails
                }
                return BadRequest(new
                {
                    error,
                    error_description = error_description ?? "Wallet returned an authorization error"
                });
            }

            if (string.IsNullOrEmpty(vp_token))
            {
                return BadRequest(new
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
            try
            {
                var docTypeForAlg = context.Dbdocumenttypes.Where(d => d.TypeId == session.DocTypeId).FirstOrDefault();
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
                // ✅ เพิ่มตรงนี้ — แก้ vp_token ถ้าเป็น JSON array
                if (!string.IsNullOrEmpty(vp_token) && vp_token.TrimStart().StartsWith("["))
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
                    return BadRequest(new
                    {
                        error = "invalid_request",
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
                            return BadRequest(new
                            {
                                error = "invalid_request",
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
                            return BadRequest(new
                            {
                                error = "invalid_request",
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
                            return BadRequest(new
                            {
                                error = "invalid_request",
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
                                return BadRequest(new
                                {
                                    error = "invalid_request",
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
                                return BadRequest(new
                                {
                                    error = "invalid_request",
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
                            return BadRequest(new
                            {
                                error = "invalid_request",
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
                        return BadRequest(new
                        {
                            error = "invalid_request",
                            error_description = "Present VP is invalid"
                        });
                    }

                }
                else
                {

                    return BadRequest(new
                    {
                        error = "invalid_request",
                        error_description = "Present VP is invalid"
                    });
                }

            }
            catch (Exception e)
            {
                return BadRequest(new
                {
                    error = "invalid_request",
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
                    string v when v.EndsWith("BootCampCredential") => "BootCamp",
                    string v when v.EndsWith("TranscriptCredential") => "TranscriptCredential_dc+sd-jwt",
                    string v when v.EndsWith("Iso18013DriversLicenseCredential") => "Iso18013DriversLicenseCredential_dc+sd-jwt",
                    string v when v.EndsWith("IDCard") => "IDCard_dc+sd-jwt",
                    _ => null
                };

                string url = HttpContext.Request.IsHttps ? "https://" : "http://";
                var externalBase = Environment.GetEnvironmentVariable("BASE_URL") ?? $"{url}{Request.Host}";
                baseUrl = $"{externalBase}/PresentResult/Result/{state}";
                logger.Info($"result => {docType}");
                if (docType == "BootCamp")
                {
                    baseUrl = $"{externalBase}/PresentResult/BootCamp/{state}";
                }

                //save to result to db
                Dbverifierresponse dbresult = new Dbverifierresponse();

                //dbresult.Id = vpServ.GetGUID();
                dbresult.SessionId = state;
                dbresult.VpToken = vp_payload;
                dbresult.VcPayload = vc_token;// vctoken;
                dbresult.PresentationSubmission = null;
                dbresult.ResponseCode = "200";
                dbresult.ReceivedAt = DateTime.UtcNow;

                var oldResult = context.Dbverifierresponses.Where(i => i.SessionId == state).FirstOrDefault();
                if (oldResult != null)
                {
                    //update
                    //oldResult.SessionId = stateid;
                    oldResult.VpToken = vp_payload;
                    oldResult.VcPayload = vc_token;
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
                    error = "invalid_request",
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
