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

        //[Route("/generate-vp-qr")]
        //[HttpPost]
        //public IActionResult VerifierPresentVP([FromBody] GenerateVpQrRequest docType)
        //{

        //    VCService vcServ = new VCService();
        //    DBService dbServ = new DBService();
        //    VpRequestSession model = new VpRequestSession();

        //    baseUrl = Environment.GetEnvironmentVariable("INTERNAL_BASE_URL")
        //      ?? $"{Request.Scheme}://{Request.Host}"; 
        //    model = dbServ.SaveVerifierSession(docType.DocumentType.ToString());
        //    string nonce = model.nonce;
        //    string stateid = model.stateId;


        //    string request_uri = $"{baseUrl}/openid4vc/request/{stateid}";
        //    var vp = "client_id=redirect_uri:" + $"{baseUrl}/openid4vc/verify/{stateid}"
        //                                       + "&request_uri=" + request_uri;

        //    string authorizationRequestUri = "openid4vp://authorize?" + vp;
        //    string QRCode = vcServ.GenerateQrCodeBase64("openid4vp://authorize?" + vp);

        //    //DBService serv = new DBService();
        //    //serv.SaveRequest(AppContextHelper.UserId, stateid, "VP");
        //    var response = new GenerateVpQrResponse
        //    {
        //        AuthorizationRequestUri = authorizationRequestUri,
        //        QrText = authorizationRequestUri,
        //        QrImageBase64 = QRCode,
        //        State = stateid,
        //        Nonce = nonce
        //    };

        //    return Ok(response);
        //}

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

        private object BuildDcqlQuery(DocumentType docType)
        {
            return docType switch
            {
                DocumentType.Transcript => new
                {
                    credentials = new[]
                    {
                    new
                    {
                        id = "transcript_credential",
                        format = "jwt_vc_json",
                        meta = new
                        {
                            type_values = new[]
                            {
                                new[]
                                {
                                    "VerifiableCredential",
                                    "TranscriptCredential"
                                }
                            }
                        }
                    }
                }
                },

                DocumentType.IDCard => new
                {
                    credentials = new[]
                    {
                    new
                    {
                        id = "idcard_credential",
                        format = "jwt_vc_json",
                        meta = new
                        {
                            type_values = new[]
                            {
                                new []
                                {
                                    "VerifiableCredential",
                                    "IDCardCredential"
                                }

                            }
                        }
                    }
                }
                },

                DocumentType.DriverLicense => new
                {
                    credentials = new[]
                    {
                    new
                    {
                        id = "driverlicense_credential",
                        format = "jwt_vc_json",
                        meta = new
                        {
                            type_values = new[]
                            {
                                new []
                                {
                                    "VerifiableCredential",
                                    "DriverLicenseCredential"
                                }

                            }
                        }
                    }
                }
                },

                _ => throw new ArgumentOutOfRangeException(nameof(docType), docType, null)
            };
        }

        

        

        private object BuildPresentationDefinition(Dbdocumenttype docType)
        {
            var vcTypes = JsonConvert.DeserializeObject<string[]>(docType.VcType)
                          ?? throw new InvalidOperationException($"VcType invalid: {docType.VcType}");
            var algValues = JsonConvert.DeserializeObject<string[]>(docType.AlgValues)
                            ?? new[] { "ES256" };

            string format = docType.Format?.ToLower();

            // ใช้ public issuer URL (BASE_URL ของ issuer) สำหรับ vct filter
            // credential ถูก issue ด้วย ISSUER_PUBLIC_URL → ต้องตรง
            // ISSUER_PUBLIC_URL หรือ fallback ไปดูจาก ISSUER_BASE_URL
            string issuerPublicUrl = Environment.GetEnvironmentVariable("ISSUER_PUBLIC_URL")
              ?? Environment.GetEnvironmentVariable("ISSUER_BASE_URL")
              ?? Environment.GetEnvironmentVariable("IssuerUrl"); 

            string descriptorId = docType.DocType?.ToLower().Replace(" ", "_") + "_descriptor";

            if (format == "dc+sd-jwt" || format == "vc+sd-jwt")
            {
                // SD-JWT: ใช้ format ตรงๆ จาก DB, กรอง $.vct ด้วย public issuer URL
                return new
                {
                    id = "vp_request_" + docType.DocType,
                    input_descriptors = new[]
                    {
                        new
                        {
                            id = descriptorId,
                            format = new Dictionary<string, object>
                            {
                                [format] = new { alg = algValues }
                            },
                            constraints = new
                            {
                                fields = new[]
                                {
                                    new
                                    {
                                        path = new[] { "$.vct" },
                                        filter = new
                                        {
                                            type = "string",
                                            @const = issuerPublicUrl + "/credentials/" + docType.Endpoint
                                        }
                                    }
                                }
                            }
                        }
                    }
                };
            }

            // jwt_vc_json: กรอง $.vc.type ด้วย type สุดท้ายใน vcTypes array
            string credentialType = vcTypes.LastOrDefault() ?? vcTypes[0];
            return new
            {
                id = "vp_request_" + docType.DocType,
                input_descriptors = new[]
                {
                    new
                    {
                        id = descriptorId,
                        format = new Dictionary<string, object>
                        {
                            [format ?? "jwt_vc_json"] = new { alg = algValues }
                        },
                        constraints = new
                        {
                            fields = new[]
                            {
                                new
                                {
                                    path = new[] { "$.vc.type" },
                                    filter = new
                                    {
                                        type = "array",
                                        contains = new
                                        {
                                            type = "string",
                                            @const = credentialType
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            };
        }

        private object BuildDcqlQuery(string docType)
        {
            return docType switch
            {
                "Transcript" => new
                {
                    credentials = new[]
                    {
                    new
                    {
                        id = "transcript_credential",
                        format = "jwt_vc_json",
                        meta = new
                        {
                            type_values = new[]
                            {
                                new[]
                                {
                                    "VerifiableCredential",
                                    "TranscriptCredential"
                                }
                            }
                        }
                    }
                }
                },

                "IDCard" => new
                {
                    credentials = new[]
                    {
                    new
                    {
                        id = "idcard_credential",
                        format = "jwt_vc_json",
                        meta = new
                        {
                            type_values = new[]
                            {
                                new []
                                {
                                    "VerifiableCredential",
                                    "IDCardCredential"
                                }

                            }
                        }
                    }
                }
                },

                "DriverLicense" => new
                {
                    credentials = new[]
                    {
                    new
                    {
                        id = "driverlicense_credential",
                        format = "jwt_vc_json",
                        meta = new
                        {
                            type_values = new[]
                            {
                                new []
                                {
                                    "VerifiableCredential",
                                    "DriverLicenseCredential"
                                }

                            }
                        }
                    }
                }
                },

                _ => throw new ArgumentOutOfRangeException(nameof(docType), docType, null)
            };
        }

        [Route("request/{id}")]
        [HttpGet]
        public async Task<IActionResult> RequestURI(string id)
        {

            VCService vcServ = new VCService();
            DBService dbServ = new DBService();
            
            var baseUrl = $"{Request.Scheme}://{Request.Host}";
            string nonce = id;
            string stateid = id;
            Dbdocumenttype docType =  dbServ.GetRequestDocType(id);


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
                client_id = $"redirect_uri:{baseUrl}/openid4vc/verify/{stateid}",
                response_mode = "direct_post",
                state = stateid,
                dcql_query = vcServ.BuildDcqlQuery(docType, Request),
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
        public async Task<IActionResult> VerifierVP([FromForm] string vp_token, [FromForm] string state)//[FromForm] string presentation_submission,)
        {

            VCService vpServ = new VCService();
            string vc_token = null;
            string vctoken = null;
            string vcResult = null;
            string vp_payload = null;
            string stateid = null;
            string details = null;
            string vpTokenForResolve = null;
            try
            {

                logger.Info($"vp_tojen => {vp_token}");
                // ✅ เพิ่มตรงนี้ — แก้ vp_token ถ้าเป็น JSON array
                if (!string.IsNullOrEmpty(vp_token) && vp_token.TrimStart().StartsWith("["))
                {
                    try
                    {
                        var arr = System.Text.Json.JsonSerializer.Deserialize<string[]>(vp_token);
                        vp_token = arr?.FirstOrDefault() ?? vp_token;
                        logger.Info($"vp_token extracted from array: {vp_token?.Substring(0, Math.Min(50, vp_token?.Length ?? 0))}");
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
                    logger.Info($"SD-JWT detected, using JWT part: {vpTokenForResolve.Substring(0, Math.Min(30, vpTokenForResolve.Length))}...");
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

                Task<string> x = vpServ.ResolveDID(didkey);
                logger.Info($"vp_token => {vpTokenForResolve}");
                logger.Info($"x.Result => {x.Result}");
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


                    Task<string> vc_x = vpServ.ResolveDID(issuer_did);
                    logger.Info($"issuer_did => {issuer_did}");
                    logger.Info($"vctoken => {vctoken}");
                    logger.Info($"jwtForVerify => {jwtForVerify?.Substring(0, 20)}...");
                    logger.Info($"vc_x.Result => {vc_x.Result}");
                    //check vc jws

                    if (vpServ.VerifyJWS(jwtForVerify, vc_x.Result, out ErrMsg))
                    {
                        //vcModel = vpServ.ResolvePublicKey(vctoken);
                        //byte[] vcDecode = vpServ.Base64UrlDecode(vcModel.payload);
                        //vcResult = Encoding.UTF8.GetString(vcDecode);
                        //vc_token = vcModel.payload;

                        vcModel = vpServ.ResolvePublicKey(jwtForVerify);
                        byte[] vcDecode = vpServ.Base64UrlDecode(vcModel.payload);
                        vcResult = Encoding.UTF8.GetString(vcDecode);
                        vc_token = vp_token?.Trim(); // เก็บ VC เต็ม (รวม ~ disclosures ถ้าเป็น SD-JWT)
                        logger.Info($"VC verify passed, isSdJwt={isSdJwt}");

                        //decodeURIComponent()
                        //**var data = Json(vcResult);
                        //logs.Add(JsonSerializer.Serialize(request, new JsonSerializerOptions { WriteIndented = true }));
                        // logs.Add(JsonSerializer.Serialize("========= Result VC ==========", new JsonSerializerOptions { WriteIndented = true }));
                        //logs.Add(JsonSerializer.Serialize(vcResult, new JsonSerializerOptions { WriteIndented = true }));
                    }
                    else
                    {
                        logger.Info($"VC verify failed: {ErrMsg}");
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
                VerifierDbContext context = new VerifierDbContext();
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


        [Route("vp/{id}")]
        [HttpGet]
        [Tags("Verifier")]
        public IActionResult GetVP(string id)
        {
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
        }

        [HttpGet("/verifier/status/{sessionId}")]
        public IActionResult GetScanStatus(string sessionId)
        {
            if (string.IsNullOrWhiteSpace(sessionId))
                return BadRequest(new { status = "failed", error = "missing_session_id" });

            var context = new VerifierDbContext();
            var result = context.Dbverifierresponses
                .Where(r => r.SessionId == sessionId)
                .FirstOrDefault();

            // ยังไม่มีแถวเลย = wallet ยังไม่ได้ verify ผ่าน (หรือยังไม่ได้ส่งอะไรกลับมาเลย)
            // สองกรณีนี้แยกกันไม่ออกจาก DB อย่างเดียว เพราะ VerifierVP ไม่เซฟ row เมื่อ verify ไม่ผ่าน
            if (result == null || (string.IsNullOrWhiteSpace(result.VpToken) && string.IsNullOrWhiteSpace(result.VcPayload)))
                return Ok(new { status = "pending" });

            var claims = ParseClaimsFromVcPayload(result.VcPayload);
            return Ok(new { status = "completed", claims });
        }

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
        /*public async Task<IActionResult> VerifierVP_old([FromForm] string vp_token,  [FromForm] string state)//[FromForm] string presentation_submission,)
        {

            VCService vpServ = new VCService();
            string vc_token = null;
            string vctoken = null;
            string vcResult = null;
            string vp_payload = null;
            string stateid = null;
            string details = null;
            try
            {

                JWSModel jwsModel = vpServ.ResolvePublicKey(vp_token?.Trim());
                jwsModel.vptoken = vp_token?.Trim();
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

                Task<string> x = vpServ.ResolveDID(didkey);
                logger.Info($"vp_token => {vp_token}");
                logger.Info($"x.Result => {x.Result}");
                if (vpServ.VerifyJWS(vp_token?.Trim(), x.Result, out string ErrMsg))
                {
                    //logs.Add(JsonSerializer.Serialize("Start Verify VC", new JsonSerializerOptions { WriteIndented = true }));

                    //verify vc
                    JWSModel vcModel = vpServ.ResolvePublicKey(vp_token?.Trim());
                    vp_payload = vcModel.payload;
                    stateid = vpServ.ResolveStateID(vcModel.payload);
                    vctoken = vpServ.VerifyVCToken(vcModel.payload);
                    vcModel = vpServ.ResolvePublicKey(vctoken);

                    string issuer_did = vcModel.didkey;
                    //logs.Add(JsonSerializer.Serialize("vc token => " + vctoken, new JsonSerializerOptions { WriteIndented = true }));

                    // ตรวจสอบว่าเป็น SD-JWT หรือไม่
                    bool isSdJwt = vctoken != null && vctoken.Contains('~');
                    string jwtForVerify = isSdJwt ? vctoken.Split('~')[0] : vctoken;
                    vcModel = vpServ.ResolvePublicKey(jwtForVerify);
                    issuer_did = vcModel.didkey;


                    Task<string> vc_x = vpServ.ResolveDID(issuer_did);
                    logger.Info($"issuer_did => {issuer_did}");
                    logger.Info($"vctoken => {vctoken}");
                    logger.Info($"vc_x.Result => {vc_x.Result}");
                    //check vc jws

                    if (vpServ.VerifyJWS(jwtForVerify, vc_x.Result, out ErrMsg))
                    {
                        //vcModel = vpServ.ResolvePublicKey(vctoken);
                        //byte[] vcDecode = vpServ.Base64UrlDecode(vcModel.payload);
                        //vcResult = Encoding.UTF8.GetString(vcDecode);
                        //vc_token = vcModel.payload;

                        vcModel = vpServ.ResolvePublicKey(jwtForVerify);
                        byte[] vcDecode = vpServ.Base64UrlDecode(vcModel.payload);
                        vcResult = Encoding.UTF8.GetString(vcDecode);
                        vc_token = vctoken; // เก็บ VC เต็ม (รวม ~ disclosures ถ้าเป็น SD-JWT)

                        //decodeURIComponent()
                        //**var data = Json(vcResult);
                        //logs.Add(JsonSerializer.Serialize(request, new JsonSerializerOptions { WriteIndented = true }));
                        // logs.Add(JsonSerializer.Serialize("========= Result VC ==========", new JsonSerializerOptions { WriteIndented = true }));
                        //logs.Add(JsonSerializer.Serialize(vcResult, new JsonSerializerOptions { WriteIndented = true }));
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

                string url = HttpContext.Request.IsHttps ? "https://" : "http://";
                var externalBase = Environment.GetEnvironmentVariable("BASE_URL") ?? $"{url}{Request.Host}";
                baseUrl = $"{externalBase}/PresentResult/Result/{state}";


                //save to result to db
                VerifierDbContext context = new VerifierDbContext();
                Dbverifierresponse dbresult = new Dbverifierresponse();

                //dbresult.Id = vpServ.GetGUID();
                dbresult.SessionId = state;
                dbresult.VpToken = vp_payload;
                dbresult.VcPayload = vctoken;
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

        } */
    }
 
}
