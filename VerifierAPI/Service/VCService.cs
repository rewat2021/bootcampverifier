using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using NLog;
using NSec.Cryptography;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using QRCoder;
using SimpleBase;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using VerifierAPI.Databases;
using VerifierAPI.Models;


namespace VerifierAPI.Service
{

    public class JWSModel
    {
        public string header { get; set; }
        public string payload { get; set; }
        public string proof { get; set; }
        public string publicKey { get; set; }
        public string didkey { get; set; }
        // FIX (Phase 1 item 6 / H-06, 2026-08-09): the base DID (fragment stripped)
        // used for the resolver HTTP call. `kidFull` preserves the exact `kid`
        // (including the "#..." fragment) so the correct verificationMethod can be
        // selected out of a DID document that lists more than one key.
        public string kidFull { get; set; }
        public string vptoken { get; set; }
        public string vctoken { get; set; }

        public string statusCode { get; set; }
        public string statusName { get; set; }

        public JWSModel(string header, string payload, string proof)
        {
            this.header = header;
            this.payload = payload;
            this.proof = proof;
        }
        public JWSModel()
        {
            //
        }
    }

    public class VCService
    {
        // FIX (silent DID-resolution failure diagnosability, 2026-08-21): ResolveDID
        // below used to swallow every failure with Console.WriteLine(e), which does not
        // reach the NLog file the app's other logging goes to — a resolver timeout,
        // non-200 response, or "no verificationMethod matched" all looked identical
        // from the outside: ResolveDID silently returned null, and the caller
        // (VerifierController.VerifierVP -> VerifyJWS) then hit an unguarded
        // NullReferenceException ("Object reference not set to an instance of an
        // object.") with no indication *why* the key never resolved.
        private static readonly Logger logger = LogManager.GetCurrentClassLogger();

        public JWSModel jwsModel { get; set; }
        public VCService()
        {
            jwsModel = new JWSModel(null, null, null);
        }

        public string GenerateIssuerDID()
        {
            byte versionByte = 1;
            var prefix = "z";
            byte[] random = new Byte[17];
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            rng.GetBytes(random);
            random[0] = versionByte;
            var msi = prefix + Base58.Bitcoin.Encode(random);
            var legalEntityDID = "did:tbsi:" + msi;

            return legalEntityDID;
        }

        public string Base64UrlDecodeToString(string input)
        {
            string base64 = input.Replace('-', '+').Replace('_', '/');

            // Pad with '=' characters if necessary
            while (base64.Length % 4 != 0)
            {
                base64 += '=';
            }

            byte[] bytes = Convert.FromBase64String(base64);
            return Encoding.UTF8.GetString(bytes);
        }

        public byte[] Base64UrlDecode(string base64Url)
        {
            // Replace '-' with '+' and '_' with '/'
            string base64 = base64Url.Replace('-', '+').Replace('_', '/');

            // Pad with '=' to make the length a multiple of 4
            switch (base64.Length % 4)
            {
                case 2:
                    base64 += "==";
                    break;
                case 3:
                    base64 += "=";
                    break;
            }

            // Convert from Base64 to bytes
            return Convert.FromBase64String(base64);
        }

        public string CheckHttps(string Protocol)
        {

            string result = null;
            if ((Protocol == null) | Protocol == "0")
            {
                result = "http://";
            }

            else
            {
                result = "https://";
            }

            return result;
        }

        public  string GenerateQrCodeBase64(string data)
        {
            QRCodeGenerator qRCodeGenerator = new QRCodeGenerator();
            var QRData = qRCodeGenerator.CreateQrCode(data, QRCoder.QRCodeGenerator.ECCLevel.Q);
            QRCoder.Base64QRCode base64qr = new QRCoder.Base64QRCode(QRData);
            var result = base64qr.GetGraphic(7);
            return result;
        }

        // FIX (did:web resolution, 2026-08-21): the Issuer's DID is did:web, which is
        // NOT resolved through a universal-resolver-style "/1.0/identifiers/{did}"
        // proxy endpoint like resolver-test.etda.or.th — that endpoint has no did:web
        // driver, so every did:web lookup was silently returning null (see the
        // ResolveDID logging added just above: this is what
        // "Outer VP JWS verify failed: Object reference not set to an instance of an
        // object." traced back to). Per the did:web spec
        // (https://w3c-ccg.github.io/did-method-web/), a did:web DID resolves by
        // transforming it directly into an HTTPS URL on the domain it names and
        // fetching the DID document from there — no resolver service involved at all:
        //   did:web:example.com                  -> https://example.com/.well-known/did.json
        //   did:web:example.com:issuer            -> https://example.com/issuer/did.json
        //   did:web:example.com%3A455:issuer      -> https://example.com:455/issuer/did.json
        // (a literal ":" after the domain is a path separator; a port number is
        // percent-encoded as %3A per the spec, since colon there would otherwise be
        // ambiguous with a path segment).
        private static string BuildDidWebUrl(string did)
        {
            const string prefix = "did:web:";
            string rest = did.Substring(prefix.Length);
            var segments = rest.Split(':').Select(Uri.UnescapeDataString).ToArray();
            if (segments.Length == 0 || string.IsNullOrEmpty(segments[0]))
                throw new ArgumentException($"Malformed did:web identifier: '{did}'");

            string domain = segments[0];
            return segments.Length == 1
                ? $"https://{domain}/.well-known/did.json"
                : $"https://{domain}/{string.Join("/", segments.Skip(1))}/did.json";
        }

        // FIX (native did:key resolution, 2026-08-21): switched DID resolution over to
        // did:key — per the did:key spec, did:key is fully self-certifying (the DID
        // string itself IS the multicodec+multibase-encoded public key), so there is
        // no resolver service involved at all, unlike did:web (fetched over HTTPS
        // from the named domain, see BuildDidWebUrl above) or a registry-backed method.
        // Decoding it locally means credential verification no longer depends on
        // resolver-test.etda.or.th having (or keeping) a working did:key driver, and
        // has no network round-trip / timeout / firewall exposure at all — the same
        // class of failure that blocked did:web resolution to issuer.zenithcomp.co.th.
        // Supports the two key types this codebase actually issues/signs with:
        //   - Ed25519: multicodec 0xed01 (2-byte prefix), matches the encoding
        //     VCService._GetDID already produces for the Verifier's own Ed25519 did:key.
        //   - P-256/secp256r1: multicodec 0x1200 (varint-encoded as {0x80,0x24}),
        //     matches BuildP256DidKeyMultibase's encoding for the Verifier's ES256
        //     did:key. The multibase value is a SEC1-*compressed* point (33 bytes);
        //     BouncyCastle's ECCurve.DecodePoint below decompresses it back to the
        //     full (x, y) needed by VerifyJWS's ES256 path (which itself only accepts
        //     uncompressed x/y, IEEE P1363 style — .NET's ECParameters has no built-in
        //     compressed-point import).
        private static string ResolveDidKeyPublicKey(string did)
        {
            const string prefix = "did:key:";
            string didOnly = did.Split('#')[0]; // did:key has at most one verification method — ignore any fragment
            if (!didOnly.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                throw new ArgumentException($"Not a did:key identifier: '{did}'");

            string multibase = didOnly.Substring(prefix.Length);
            if (multibase.Length < 2 || multibase[0] != 'z')
                throw new ArgumentException($"Unsupported did:key multibase prefix (expected 'z' / base58btc): '{did}'");

            // .ToArray() normalizes regardless of whether this SimpleBase version's
            // Decode returns byte[] or a Span<byte>/ReadOnlySpan<byte>.
            byte[] decoded = Base58.Bitcoin.Decode(multibase.Substring(1)).ToArray();

            if (decoded.Length > 2 && decoded[0] == 0xED && decoded[1] == 0x01)
            {
                // Ed25519 — raw 32-byte public key follows the 2-byte multicodec prefix.
                // Returned base64url-encoded to match the shape VerifyJWS's Ed25519 path
                // already expects (the same shape ResolveDID returns for a JWK's raw "x").
                byte[] rawKey = decoded.Skip(2).ToArray();
                return WebEncoders.Base64UrlEncode(rawKey);
            }

            if (decoded.Length > 2 && decoded[0] == 0x80 && decoded[1] == 0x24)
            {
                // P-256 — SEC1-compressed point follows the 2-byte multicodec prefix.
                byte[] compressed = decoded.Skip(2).ToArray();
                var curve = SecNamedCurves.GetByName("secp256r1").Curve;
                var point = curve.DecodePoint(compressed).Normalize();
                string x = WebEncoders.Base64UrlEncode(point.AffineXCoord.GetEncoded());
                string y = WebEncoders.Base64UrlEncode(point.AffineYCoord.GetEncoded());
                // Matches the {"crv","x","y"} shape VerifyJWS's ES256 branch expects.
                return JsonConvert.SerializeObject(new { crv = "P-256", x, y });
            }

            throw new NotSupportedException(
                $"Unsupported did:key multicodec prefix in '{did}' (first bytes: {(decoded.Length > 0 ? decoded[0] : 0):X2}{(decoded.Length > 1 ? decoded[1] : 0):X2})");
        }

        public async Task<string> ResolveDID(string key, string exactKid = null)
        {
            if (key.StartsWith("did:key:", StringComparison.OrdinalIgnoreCase))
            {
                try
                {
                    string resolved = ResolveDidKeyPublicKey(key);
                    logger.Info($"ResolveDID: resolved '{key}' locally (did:key — no network call)");
                    return resolved;
                }
                catch (Exception e)
                {
                    logger.Info($"ResolveDID: local did:key decode failed for '{key}': {e.GetType().Name}: {e.Message}");
                    return null;
                }
            }

            string publickey = null;
            try
            {
                // FIX (bounded resolver timeout, 2026-08-21): default HttpClient timeout
                // is 100s — a network-level failure (firewall silently dropping packets
                // rather than refusing the connection, as seen resolving a did:web whose
                // host was unreachable from this server) could otherwise hang the whole
                // VerifierVP request for up to that long before failing. 10s matches the
                // timeout already used for the broker HttpClient (H-10, Program.cs).
                HttpClient client = new HttpClient { Timeout = TimeSpan.FromSeconds(10) };
                // did:web resolves directly against the domain it names (see
                // BuildDidWebUrl above); every other DID method here still goes through
                // the shared universal-resolver-style proxy, unchanged.
                string url = key.StartsWith("did:web:", StringComparison.OrdinalIgnoreCase)
                    ? BuildDidWebUrl(key)
                    : $"https://resolver-test.etda.or.th/1.0/identifiers/{key}";
                logger.Info($"ResolveDID: resolving '{key}' via {url}");
                // Set request headers if needed (e.g., Accept)
                client.DefaultRequestHeaders.Accept.Clear();
                client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                HttpResponseMessage response = await client.GetAsync(url);
                response.EnsureSuccessStatusCode();

                // Read and deserialize the response content

                string jsonResponse = await response.Content.ReadAsStringAsync();
                JsonDocument document = JsonDocument.Parse(jsonResponse);
                JsonElement root = document.RootElement;

                // FIX (Phase 1 item 6 / H-06, 2026-08-09): previously this loop kept
                // overwriting `publickey` with whichever verificationMethod happened to
                // be listed last in the DID document, ignoring the exact `kid` the JWS
                // header asked for. Now it prefers the entry whose `id` matches the
                // requested kid (handling both absolute "did:...#frag" and relative
                // "#frag" id styles). If no exactKid is supplied, or none matches, it
                // falls back to the previous "last one" behavior so existing DID
                // documents with a single key keep working unchanged.
                // See OID4VP-1.0-COMPLIANCE-AUDIT.md Phase 1 item 6 / H-06.
                JsonElement? matched = null;
                JsonElement? lastSeen = null;
                foreach (JsonElement method in root.GetProperty("verificationMethod").EnumerateArray())
                {
                    lastSeen = method;
                    if (!string.IsNullOrEmpty(exactKid) && method.TryGetProperty("id", out var idEl))
                    {
                        string vmId = idEl.GetString() ?? "";
                        if (string.Equals(vmId, exactKid, StringComparison.Ordinal) ||
                            (vmId.StartsWith("#") && exactKid.EndsWith(vmId, StringComparison.Ordinal)) ||
                            (exactKid.StartsWith("#") && vmId.EndsWith(exactKid, StringComparison.Ordinal)))
                        {
                            matched = method;
                        }
                    }
                }

                JsonElement? chosen = matched ?? lastSeen;
                if (chosen == null)
                {
                    // FIX (silent DID-resolution failure diagnosability, 2026-08-21):
                    // resolver returned a DID document with no verificationMethod entries
                    // at all — not an exception, so this used to fall through and return
                    // null with zero indication of why.
                    logger.Info($"ResolveDID: DID document for '{key}' has no verificationMethod entries (exactKid={exactKid ?? "<none>"})");
                }
                if (chosen != null)
                {
                    JsonElement publicKeyJwk = chosen.Value.GetProperty("publicKeyJwk");
                    string crv = publicKeyJwk.TryGetProperty("crv", out var crvEl) ? crvEl.GetString() : null;
                    string x = publicKeyJwk.TryGetProperty("x", out var xEl) ? xEl.GetString() : null;

                    // FIX (Phase 1 item 6 / H-05, 2026-08-09): ES256 (P-256) keys need
                    // both x and y coordinates to verify; Ed25519 keys only need x.
                    // Package P-256 material as a small JSON blob so VerifyJWS can tell
                    // them apart, while Ed25519 keeps returning the raw x string exactly
                    // as before (no behavior change for the currently-working format).
                    if (string.Equals(crv, "P-256", StringComparison.OrdinalIgnoreCase))
                    {
                        string y = publicKeyJwk.TryGetProperty("y", out var yEl) ? yEl.GetString() : null;
                        publickey = JsonConvert.SerializeObject(new { crv = "P-256", x, y });
                    }
                    else
                    {
                        publickey = x;
                    }

                    if (matched == null && !string.IsNullOrEmpty(exactKid))
                    {
                        // exactKid was requested but nothing matched it — fell back to
                        // lastSeen (H-06's documented fallback behavior). Worth knowing
                        // about even though it's not a hard failure, since a Wallet/DID
                        // document mismatch here can look identical to "resolution failed"
                        // from the caller's side.
                        logger.Info($"ResolveDID: no verificationMethod matched kid='{exactKid}' in DID document for '{key}' — falling back to the last-listed key");
                    }
                }
            }
            catch (Exception e)
            {
                // FIX (silent DID-resolution failure diagnosability, 2026-08-21): was
                // Console.WriteLine(e), which never reaches the NLog file (logs/*.log)
                // the rest of the app's request logging goes to — a resolver timeout,
                // DNS failure, non-2xx response (EnsureSuccessStatusCode throws
                // HttpRequestException), or malformed DID document JSON all silently
                // returned null with nothing in the actual application log to explain
                // why. This is the real reason a signature verify can fail with a bare
                // "Object reference not set to an instance of an object." further up the
                // call chain (VerifyJWS calling Base64UrlDecode on a null key).
                logger.Info($"ResolveDID failed for key='{key}' exactKid='{exactKid ?? "<none>"}': {e.GetType().Name}: {e.Message}");
            }

            return publickey;
        }

        public string ResolveStateID(string jws)
        {
            string headerJson = Base64UrlDecodeToString(jws);
            using JsonDocument doc = JsonDocument.Parse(headerJson);
            string stateid = doc.RootElement.GetProperty("jti").GetString();

            return stateid;
        }

        public string GenStateId()
        {
            byte versionByte = 1;
            byte[] random = new Byte[8];
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            rng.GetBytes(random);
            random[0] = versionByte;
            return Base58.Bitcoin.Encode(random);
        }

        public JwtModel DecodeJWT(string token)
        {
            var result = new JwtModel();
            if (string.IsNullOrEmpty(token)) return result;
            var tokenArr = token.Split('.');
            result.Header = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(tokenArr[0]));
            result.Payload = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(tokenArr[1]));
            return result;
        }

        public JWSModel ResolvePublicKey(string jws)
        {
            bool isValid = false;
            JWSModel result = new JWSModel();


            var parts = jws.Split('.');
            if (parts.Length != 3)
                throw new ArgumentException("Invalid JWS format.");

            try
            {
                // Decode the Base64Url components
                byte[] header = WebEncoders.Base64UrlDecode(parts[0]);
                byte[] payload_ = WebEncoders.Base64UrlDecode(parts[1]);
                byte[] signature = WebEncoders.Base64UrlDecode(parts[2]);

                string headerJson = Base64UrlDecodeToString(parts[0]);
                using JsonDocument doc = JsonDocument.Parse(headerJson);
                string kid = doc.RootElement.GetProperty("kid").GetString();

                result.header = parts[0];
                result.payload = parts[1];
                result.proof = parts[2];
                result.didkey = kid;
                result.kidFull = kid; // full kid incl. fragment, for exact verificationMethod selection
                if (kid.IndexOf('#') > 0)
                {
                    result.didkey = kid.Split('#')[0];
                }



            }
            catch (Exception e)
            {
                result.statusCode = "400";
                result.statusName = e.Message;
                return result;
                //logs.Add(JsonSerializer.Serialize("Error => " + e.Message, new JsonSerializerOptions { WriteIndented = true }));
            }
            return result;
        }



        private class Es256KeyMaterial
        {
            public string crv { get; set; }
            public string x { get; set; }
            public string y { get; set; }
        }

        // FIX (Phase 1 item 6, 2026-08-09): dispatches by the JWS header's declared
        // `alg` and the shape of `publicKey`:
        //   - Ed25519 (alg "EdDSA"/"Ed25519"): `publicKey` is the raw base64url JWK
        //     `x` value, exactly as before — this path is unchanged so the format
        //     that already works in production keeps working identically.
        //   - ES256 (alg "ES256"): `publicKey` is a small JSON blob
        //     {"crv":"P-256","x":...,"y":...} produced by ResolveDID. Previously
        //     ES256 credentials could never verify at all (H-05) even though
        //     AlgValues configures ES256 for some document types.
        // `permittedAlgs`, when supplied, rejects any signature whose header `alg`
        // isn't in the caller's allow-list (e.g. this document type's configured
        // AlgValues), instead of accepting whatever algorithm the token happens to
        // use. Left null at call sites that don't yet have that context, which
        // preserves prior behavior there.
        // See OID4VP-1.0-COMPLIANCE-AUDIT.md Phase 1 item 6 / H-05 / H-06.
        public bool VerifyJWS(string jws, string publicKey, out string ErrMsg, string[] permittedAlgs = null)
        {
            ErrMsg = null;
            bool isValid = false;

            var parts = jws.Split('.');
            if (parts.Length != 3)
                throw new ArgumentException("Invalid JWS format.");

            try
            {
                // Decode the Base64Url components
                byte[] header = WebEncoders.Base64UrlDecode(parts[0]);
                byte[] payload_ = WebEncoders.Base64UrlDecode(parts[1]);
                byte[] signature = WebEncoders.Base64UrlDecode(parts[2]);

                jwsModel.header = parts[0];
                jwsModel.payload = parts[1];
                jwsModel.proof = parts[2];

                string headerJson = Base64UrlDecodeToString(parts[0]);
                using JsonDocument headerDoc = JsonDocument.Parse(headerJson);
                string alg = headerDoc.RootElement.TryGetProperty("alg", out var algEl) ? algEl.GetString() : null;

                if (permittedAlgs != null && permittedAlgs.Length > 0 &&
                    !permittedAlgs.Any(a => string.Equals(a, alg, StringComparison.OrdinalIgnoreCase)))
                {
                    ErrMsg = $"alg '{alg}' is not in the permitted algorithm list for this credential type";
                    return false;
                }

                // Reconstruct the signed data (Header + '.' + Payload)
                byte[] signedData = System.Text.Encoding.UTF8.GetBytes(parts[0] + "." + parts[1]);

                bool looksLikeEs256Blob = !string.IsNullOrWhiteSpace(publicKey) && publicKey.TrimStart().StartsWith("{");

                if (string.Equals(alg, "ES256", StringComparison.OrdinalIgnoreCase) || looksLikeEs256Blob)
                {
                    if (!looksLikeEs256Blob)
                    {
                        ErrMsg = "alg is ES256 but no P-256 key material was resolved";
                        return false;
                    }

                    var keyMaterial = JsonConvert.DeserializeObject<Es256KeyMaterial>(publicKey);
                    if (keyMaterial == null || string.IsNullOrEmpty(keyMaterial.x) || string.IsNullOrEmpty(keyMaterial.y))
                    {
                        ErrMsg = "Incomplete ES256 (P-256) key material";
                        return false;
                    }

                    var ecParams = new ECParameters
                    {
                        Curve = ECCurve.NamedCurves.nistP256,
                        Q = new ECPoint
                        {
                            X = Base64UrlDecode(keyMaterial.x),
                            Y = Base64UrlDecode(keyMaterial.y)
                        }
                    };
                    using var ecdsa = ECDsa.Create(ecParams);
                    // JOSE ES256 signatures are the raw r||s (64-byte) IEEE P1363 format,
                    // not ASN.1 DER, and are always signed over SHA-256.
                    isValid = ecdsa.VerifyData(signedData, signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
                    if (!isValid)
                    {
                        ErrMsg = "vp_token is invalid";
                    }
                    return isValid;
                }

                // Ed25519 path — identical to the previous (only) implementation, plus a
                // guard for a null/empty key. FIX (silent DID-resolution failure
                // diagnosability, 2026-08-21): previously this called
                // Base64UrlDecode(publicKey) unguarded — if the caller's DID resolution
                // failed and passed through a null key (see VCService.ResolveDID), this
                // threw a bare, unhelpful NullReferenceException ("Object reference not
                // set to an instance of an object.") deep inside Base64UrlDecode instead
                // of a diagnosable error, matching the existing guard already present in
                // the ES256 branch just above.
                if (string.IsNullOrWhiteSpace(publicKey))
                {
                    ErrMsg = "no public key was resolved for this credential's signer (DID resolution likely failed — see ResolveDID log)";
                    return false;
                }
                byte[] base64Encode = Base64UrlDecode(publicKey);
                var key = PublicKey.Import(SignatureAlgorithm.Ed25519, base64Encode, KeyBlobFormat.RawPublicKey);
                isValid = SignatureAlgorithm.Ed25519.Verify(key, signedData, signature);
                if (!isValid)
                {
                    ErrMsg = "vp_token is invalid";
                }
            }
            catch (Exception e)
            {
                ErrMsg = e.Message;
                return false;
            }
            return isValid;

        }

        //public bool VerifyJWS(string jws, string publicKey, out string ErrMsg)
        //{
        //    ErrMsg = null;
        //    try
        //    {
        //        Console.WriteLine(jws);
        //        var parts = jws.Split('.');
        //        if (parts.Length != 3)
        //            throw new ArgumentException("Invalid JWS format.");

        //        // publicKey คือ x จาก JWK ซึ่งเป็น Base64Url encoded Ed25519 public key
        //        byte[] keyBytes = WebEncoders.Base64UrlDecode(publicKey);
        //        byte[] signature = WebEncoders.Base64UrlDecode(parts[2]);
        //        byte[] signedData = Encoding.UTF8.GetBytes(parts[0] + "." + parts[1]);

        //        // Import Ed25519 public key (32 bytes raw)
        //        var key = PublicKey.Import(
        //            SignatureAlgorithm.Ed25519,
        //            keyBytes,
        //            KeyBlobFormat.RawPublicKey
        //        );

        //        bool isValid = SignatureAlgorithm.Ed25519.Verify(key, signedData, signature);
        //        if (!isValid) ErrMsg = "vp_token is invalid";
        //        return isValid;
        //    }
        //    catch (Exception e)
        //    {
        //        ErrMsg = e.Message;
        //        return false;
        //    }
        //}


        public string VerifyVCToken(string vp_payload)
        {
            string vc_token = null;
            try
            {
                string payload = Base64UrlDecodeToString(vp_payload);

                // ลองดูก่อนว่าเป็น SD-JWT direct (dc+sd-jwt) หรือ VP wrapper
                var json = JsonConvert.DeserializeObject<dynamic>(payload);

                // ถ้ามี vp.verifiableCredential = jwt_vc_json format
                if (json?.vp?.verifiableCredential != null)
                {
                    Root rootObject = JsonConvert.DeserializeObject<Root>(payload);
                    vc_token = rootObject.Vp.VerifiableCredential[0]?.Trim();
                }
                // ถ้ามี vct = dc+sd-jwt format (SD-JWT ตรงๆ)
                else if (json?.vct != null)
                {
                    // vp_token คือ SD-JWT ตัว VC เลย ไม่มี wrapper
                    // ต้อง return กลับไปจาก vp_token โดยตรง
                    vc_token = null; // จะ handle ใน VerifierVP แทน
                }
            }
            catch (Exception e)
            {
            }
            return vc_token;
        }

        public string GetKey(bool isPrivate, IWebHostEnvironment _env)
        {
            var client = "Tester";
            var privateKey = "";
            var publicKey = "";

            privateKey = Database.Read(client, "privateKey", _env);
            publicKey = Database.Read(client, "publicKey", _env);

            if (string.IsNullOrEmpty(privateKey) || string.IsNullOrEmpty(publicKey))
            {
                var keyPairGenerator = new Ed25519KeyPairGenerator();
                keyPairGenerator.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
                var keyPair = keyPairGenerator.GenerateKeyPair();

                var privateKeyEd25519 = (Ed25519PrivateKeyParameters)keyPair.Private;
                var publicKeyEd25519 = (Ed25519PublicKeyParameters)keyPair.Public;

                using (var memoryStream = new MemoryStream())
                {
                    var pemWriter = new PemWriter(new StreamWriter(memoryStream));
                    pemWriter.WriteObject(privateKeyEd25519);
                    pemWriter.Writer.Flush();
                    privateKey = Encoding.UTF8.GetString(memoryStream.ToArray());
                }
                var temp = Convert.ToBase64String(publicKeyEd25519.GetEncoded());
                using (var memoryStream = new MemoryStream())
                {
                    var pemWriter = new PemWriter(new StreamWriter(memoryStream));
                    pemWriter.WriteObject(publicKeyEd25519);
                    pemWriter.Writer.Flush();
                    publicKey = Encoding.UTF8.GetString(memoryStream.ToArray());
                }


                Database.Write(client, "privateKey", privateKey, _env);
                Database.Write(client, "publicKey", publicKey, _env);
            }

            if (isPrivate) return privateKey;
            else return publicKey;
        }

        public string GetSubKey(bool isPrivate, IWebHostEnvironment _env)
        {
            var client = "Tester";
            var privateKey = "";
            var publicKey = "";

            privateKey = Database.Read(client, "subPrivate", _env);
            publicKey = Database.Read(client, "subPublic", _env);

            if (string.IsNullOrEmpty(privateKey) || string.IsNullOrEmpty(publicKey))
            {
                var keyPairGenerator = new Ed25519KeyPairGenerator();
                keyPairGenerator.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
                var keyPair = keyPairGenerator.GenerateKeyPair();

                var privateKeyEd25519 = (Ed25519PrivateKeyParameters)keyPair.Private;
                var publicKeyEd25519 = (Ed25519PublicKeyParameters)keyPair.Public;

                using (var memoryStream = new MemoryStream())
                {
                    var pemWriter = new PemWriter(new StreamWriter(memoryStream));
                    pemWriter.WriteObject(privateKeyEd25519);
                    pemWriter.Writer.Flush();
                    privateKey = Encoding.UTF8.GetString(memoryStream.ToArray());
                }
                var temp = Convert.ToBase64String(publicKeyEd25519.GetEncoded());
                using (var memoryStream = new MemoryStream())
                {
                    var pemWriter = new PemWriter(new StreamWriter(memoryStream));
                    pemWriter.WriteObject(publicKeyEd25519);
                    pemWriter.Writer.Flush();
                    publicKey = Encoding.UTF8.GetString(memoryStream.ToArray());
                }


                Database.Write(client, "subPrivate", privateKey, _env);
                Database.Write(client, "subPublic", publicKey, _env);
            }

            if (isPrivate) return privateKey;
            else return publicKey;
        }

        public string _GetDID(IWebHostEnvironment _env)
        {
            var client = "Tester";
            //var privateKey = Database.Read(client, "privateKey", _env);
            var publicKey = Database.Read(client, "publicKey", _env);
            var diddoc = Database.ReadDID(client, "DID", _env);

            if (string.IsNullOrEmpty(diddoc))
            {
                VCService serv = new VCService();
                PemReader pemReaderPublic = new PemReader(new StringReader(serv.GetKey(false, _env)));
                //Ed25519PrivateKeyParameters privateKeyEd25519 = (Ed25519PrivateKeyParameters)pemReaderPublic.ReadObject();
                Ed25519PublicKeyParameters publicKeyEd25519 = (Ed25519PublicKeyParameters)pemReaderPublic.ReadObject();

                byte[] publicKeyBytes = publicKeyEd25519.GetEncoded();
                byte[] multicodecPrefix = new byte[] { 0xED, 0x01 };

                byte[] privateKeyWithPrefix = new byte[multicodecPrefix.Length + publicKeyBytes.Length];

                Buffer.BlockCopy(multicodecPrefix, 0, privateKeyWithPrefix, 0, multicodecPrefix.Length);
                Buffer.BlockCopy(publicKeyBytes, 0, privateKeyWithPrefix, multicodecPrefix.Length, publicKeyBytes.Length);

                //var privateKeyString = "z" + Base58.Bitcoin.Encode(publicKeyEd25519.GetEncoded());
                var privateKeyString = "z" + Base58.Bitcoin.Encode(privateKeyWithPrefix);
                diddoc = "did:key:" + privateKeyString;// + "#" + privateKeyString;

                Database.Write(client, "DID", diddoc, _env);
            }


            return diddoc;
        }

        private static readonly object _es256KeyLock = new object();

        // FIX (H-01, 2026-08-10): dedicated ES256 (P-256) signing key for Verifier
        // Request Objects, separate from the Ed25519 key(s) above (GetKey/
        // GetSubKey), which the DID-based verificationMethod flow ties to
        // Issuer-side VC/JWS signing. Generated once and persisted the same way as
        // the existing keys (PEM file under the app's ContentRootPath) for
        // consistency with this codebase's existing key handling — not a
        // KMS/HSM-backed key. See OID4VP-1.0-COMPLIANCE-AUDIT.md finding H-01.
        public ECDsa GetVerifierRequestSigningKey(IWebHostEnvironment _env)
        {
            lock (_es256KeyLock)
            {
                var client = "Verifier";
                string privatePem = Database.Read(client, "verifierEs256Private", _env);
                string publicPem = Database.Read(client, "verifierEs256Public", _env);

                var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);

                if (string.IsNullOrEmpty(privatePem) || string.IsNullOrEmpty(publicPem))
                {
                    ecdsa.GenerateKey(ECCurve.NamedCurves.nistP256);
                    privatePem = ecdsa.ExportECPrivateKeyPem();
                    publicPem = ecdsa.ExportSubjectPublicKeyInfoPem();

                    Database.Write(client, "verifierEs256Private", privatePem, _env);
                    Database.Write(client, "verifierEs256Public", publicPem, _env);
                }
                else
                {
                    ecdsa.ImportFromPem(privatePem);
                }

                return ecdsa;
            }
        }

        // FIX (H-01, 2026-08-10): builds a `did:key` identifier for the Verifier's
        // ES256 key, per the W3C did:key method spec — multicodec prefix for a
        // P-256 public key (`p256-pub` = 0x1200, varint-encoded as 0x80 0x24)
        // prepended to the SEC1-compressed EC point, then base58btc-encoded with a
        // leading "z" (multibase). This DID is used as the `client_id` (instead of
        // `redirect_uri:...`) per OpenID4VP §5.9.3, which states requests using the
        // `redirect_uri` Client Identifier Prefix "cannot be signed because there
        // is no method for the Wallet to obtain a trusted key for verification."
        // did:key needs no resolver call — the DID itself deterministically encodes
        // the public key — so a Wallet that supports the `did` Client Identifier
        // Prefix and the did:key method can verify this without any network
        // lookup. See OID4VP-1.0-COMPLIANCE-AUDIT.md finding H-01.
        private static string BuildP256DidKeyMultibase(ECDsa ecdsa)
        {
            var parms = ecdsa.ExportParameters(false);
            byte[] x = parms.Q.X;
            byte[] y = parms.Q.Y;

            // SEC1 compressed point: 0x02 if Y is even, 0x03 if Y is odd, then X.
            byte prefix = (byte)((y[y.Length - 1] % 2 == 0) ? 0x02 : 0x03);
            byte[] compressed = new byte[1 + x.Length];
            compressed[0] = prefix;
            Buffer.BlockCopy(x, 0, compressed, 1, x.Length);

            byte[] multicodecPrefix = new byte[] { 0x80, 0x24 }; // p256-pub, varint-encoded
            byte[] withPrefix = new byte[multicodecPrefix.Length + compressed.Length];
            Buffer.BlockCopy(multicodecPrefix, 0, withPrefix, 0, multicodecPrefix.Length);
            Buffer.BlockCopy(compressed, 0, withPrefix, multicodecPrefix.Length, compressed.Length);

            return "z" + Base58.Bitcoin.Encode(withPrefix);
        }

        // The full `did:key:...` identifier for the Verifier's ES256 signing key.
        // Used as `client_id` in both RequestURI (inside the signed Request
        // Object) and by every caller that builds the outer by-reference
        // client_id+request_uri pair (VerifierPresentVP, VerifierRequestService) —
        // per RFC 9101 §5, the outer client_id query parameter MUST match the
        // client_id inside the Request Object once dereferenced, so both must stay
        // in sync. See OID4VP-1.0-COMPLIANCE-AUDIT.md finding H-01.
        public string GetVerifierDid(IWebHostEnvironment _env)
        {
            var ecdsa = GetVerifierRequestSigningKey(_env);
            return "did:key:" + BuildP256DidKeyMultibase(ecdsa);
        }

        // FIX (H-01, 2026-08-10) — CORRECTED: the OpenID4VP 1.0 (final) Client
        // Identifier Prefix for a DID-bound client_id is named
        // `decentralized_identifier`, not `did` — confirmed against the published
        // spec text (§5.9.3): "Example Client Identifier:
        // `decentralized_identifier:did:example:123`." A bare DID with no prefix
        // (what earlier code here used) matches none of the spec's defined
        // Client Identifier Prefixes, which is almost certainly why a real Wallet
        // rejected it with a version-inference error ("Could not infer openid4vp
        // version..."). The `kid` in the signed JWT header stays as the bare
        // `did:key:...#...` (unprefixed) — only client_id gets the
        // `decentralized_identifier:` prefix, matching the spec's own example
        // header/body pair (`"kid": "did:example:123#1"` alongside
        // `"client_id": "decentralized_identifier:did:example:123"`).
        //
        // SWITCHED BACK 2026-08-11: briefly used the Ed25519 did:key (_GetDID)
        // instead of this P-256 one (2026-08-10, in response to a Wallet JWT
        // verification failure). Per explicit instruction, reverted back to
        // ES256/P-256 (GetVerifierDid) here. IMPORTANT: the earlier P-256 failure
        // ("Error during verification of jwt") coincided with an unrelated bug —
        // an intermediate edit left `kid` pointing at a different DID than
        // `client_id` (see SignRequestObject's old comment / RequestURI's
        // comment) — which alone guarantees a verification failure regardless of
        // curve. That mismatch has since been fixed, so it is not yet known
        // whether ES256/P-256 itself was ever actually broken for the target
        // Wallet; this revert has not been re-tested live. If ES256 fails again
        // with a *different* error than before, the P-256 curve-support
        // hypothesis becomes more likely.
        // See OID4VP-1.0-COMPLIANCE-AUDIT.md finding H-01.
        public string GetVerifierClientId(IWebHostEnvironment _env)
        {
            return "decentralized_identifier:" + GetVerifierDid(_env);
        }

        // UNUSED as of 2026-08-11 (switched back to SignRequestObjectES256 below,
        // per explicit instruction to revert client_id/kid to ES256). Left in
        // place — this Ed25519 path worked in code review but was never
        // confirmed against a live Wallet before the revert. See
        // SignRequestObjectES256 below for the currently-active signer.
        // See OID4VP-1.0-COMPLIANCE-AUDIT.md finding H-01.
        public string SignRequestObject(object payloadObj, IWebHostEnvironment _env)
        {
            string did = _GetDID(_env);
            string multibase = did.Substring("did:key:".Length);
            string kid = $"{did}#{multibase}";

            string privateKeyPem = GetKey(true, _env);
            var pemReader = new PemReader(new StringReader(privateKeyPem));
            var privateKeyEd25519 = (Ed25519PrivateKeyParameters)pemReader.ReadObject();

            var headerObj = new { alg = "EdDSA", typ = "oauth-authz-req+jwt", kid = kid };
            string headerJson = JsonConvert.SerializeObject(headerObj);
            string payloadJson = JsonConvert.SerializeObject(payloadObj);
            string headerB64 = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(headerJson));
            string payloadB64 = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(payloadJson));
            string signingInput = $"{headerB64}.{payloadB64}";

            var signer = new Ed25519Signer();
            signer.Init(true, privateKeyEd25519);
            byte[] signingBytes = Encoding.UTF8.GetBytes(signingInput);
            signer.BlockUpdate(signingBytes, 0, signingBytes.Length);
            byte[] signature = signer.GenerateSignature();
            string sigB64 = WebEncoders.Base64UrlEncode(signature);

            return $"{signingInput}.{sigB64}";
        }

        // Signs an OpenID4VP Request Object with the Verifier's own ES256 key —
        // UNUSED as of 2026-08-10, see SignRequestObject above for why signing
        // switched to Ed25519. Left in place in case P-256 is revisited. `kid` is
        // the did:key verificationMethod id (`<did>#<multibase>`), the standard
        // convention a did:key resolver expects. Uses the same raw r||s
        // (IeeeP1363FixedFieldConcatenation) signature format that VerifyJWS's
        // ES256 verification path already expects elsewhere in this file, so the
        // signature format is consistent across sign and verify in this codebase.
        // See OID4VP-1.0-COMPLIANCE-AUDIT.md finding H-01.
        public string SignRequestObjectES256(object payloadObj, IWebHostEnvironment _env)
        {
            var ecdsa = GetVerifierRequestSigningKey(_env);
            string multibase = BuildP256DidKeyMultibase(ecdsa);
            string did = "did:key:" + multibase;
            string kid = $"{did}#{multibase}";

            var headerObj = new { alg = "ES256", typ = "oauth-authz-req+jwt", kid = kid };
            string headerJson = JsonConvert.SerializeObject(headerObj);
            string payloadJson = JsonConvert.SerializeObject(payloadObj);
            string headerB64 = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(headerJson));
            string payloadB64 = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(payloadJson));
            string signingInput = $"{headerB64}.{payloadB64}";
            byte[] signature = ecdsa.SignData(
                Encoding.UTF8.GetBytes(signingInput),
                HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            string sigB64 = WebEncoders.Base64UrlEncode(signature);
            return $"{signingInput}.{sigB64}";
        }


        public bool IsTokenValid(IConfiguration _config, string token)
        {
            try
            {
                // Retrieve the Base64 encoded private key from configuration
                string privateKeyBase64 = _config["Jwt:PrivateKey"];
                if (string.IsNullOrEmpty(privateKeyBase64))
                {
                    // Log or handle the error as needed
                    return false;
                }

                // Convert Base64 string back to byte array
                byte[] privateKeyBytes = Convert.FromBase64String(privateKeyBase64);

                // Create an ECDsa instance with the private key
                var ecdsa = ECDsa.Create();
                ecdsa.ImportECPrivateKey(privateKeyBytes, out _);

                // Create a new ECDsaSecurityKey (you could also derive the public key from this)
                var ecdsaSecurityKey = new ECDsaSecurityKey(ecdsa);

                // Set up validation parameters
                var tokenHandler = new JwtSecurityTokenHandler();
                var validationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = ecdsaSecurityKey,
                    ValidateIssuer = true,
                    ValidIssuer = _config["Jwt:Issuer"], // The expected issuer
                    ValidateAudience = true,
                    ValidAudience = $"{_config["Jwt:Issuer"]}/credential", //"everyone", // The expected audience
                    ValidateLifetime = false, //default true
                    ClockSkew = TimeSpan.Zero // To avoid time discrepancies
                };

                // Validate the token
                var principal = tokenHandler.ValidateToken(token, validationParameters, out SecurityToken validatedToken);

                // If token is valid, return true
                return validatedToken != null;
            }
            catch (Exception ex)
            {
                // Log or handle the exception as needed
                return false;
            }
        }

        public string GetGUID()
        {
            Guid guid = Guid.NewGuid();
            return guid.ToString();
        }

        public bool IsValidJson(string jsonString)
        {
            if (string.IsNullOrWhiteSpace(jsonString))
            {
                return false; // Null or empty string is not valid JSON
            }

            try
            {
                using (JsonDocument.Parse(jsonString))
                {
                    return true; // Successfully parsed, it's valid JSON
                }
            }
           
            catch (Exception)
            {
                return false; // Catch other unexpected errors
            }
        }

        public bool IsValidNonce(string? nonce)
        {
            // Check if the nonce is null, empty, or whitespace
            if (string.IsNullOrWhiteSpace(nonce))
            {
                return false; // Nonce is undefined
            }


            // Check for valid format (e.g., base64 or alphanumeric)
            string base64Pattern = @"^[a-zA-Z0-9-_]+$";
            if (!Regex.IsMatch(nonce, base64Pattern))
            {
                return false; // Nonce format is invalid
            }

            return true; // Nonce is valid
        }

        public  bool IsValidPresentationDefinition(string? presentationDefinitionJson)
        {
            if (string.IsNullOrWhiteSpace(presentationDefinitionJson))
            {
                Console.WriteLine("Error: presentation_definition is undefined or null.");
                return false;
            }

            try
            {
                // Parse the JSON
                using var document = JsonDocument.Parse(presentationDefinitionJson);
                var root = document.RootElement;

                // Validate 'id'
                if (!root.TryGetProperty("id", out JsonElement idElement) ||
                    string.IsNullOrWhiteSpace(idElement.GetString()))
                {
                    Console.WriteLine("Error: Missing or invalid 'id' in presentation_definition.");
                    return false;
                }

                // Validate 'input_descriptors'
                if (!root.TryGetProperty("input_descriptors", out JsonElement inputDescriptorsElement) ||
                    inputDescriptorsElement.ValueKind != JsonValueKind.Array ||
                    inputDescriptorsElement.GetArrayLength() == 0)
                {
                    Console.WriteLine("Error: Missing or invalid 'input_descriptors' in presentation_definition.");
                    return false;
                }

                // Validate each input descriptor
                foreach (var descriptor in inputDescriptorsElement.EnumerateArray())
                {
                    if (!descriptor.TryGetProperty("id", out JsonElement descriptorIdElement) ||
                        string.IsNullOrWhiteSpace(descriptorIdElement.GetString()))
                    {
                        Console.WriteLine("Error: Invalid 'id' in input_descriptor.");
                        return false;
                    }

                    if (!descriptor.TryGetProperty("format", out JsonElement formatElement) ||
                        !formatElement.TryGetProperty("jwt_vc_json", out JsonElement jwtVcJson) ||
                        !jwtVcJson.TryGetProperty("alg", out JsonElement algElement) ||
                        algElement.ValueKind != JsonValueKind.Array ||
                        algElement.GetArrayLength() == 0)
                    {
                        Console.WriteLine("Error: Invalid 'format' in input_descriptor.");
                        return false;
                    }

                    if (!descriptor.TryGetProperty("constraints", out JsonElement constraintsElement) ||
                        !constraintsElement.TryGetProperty("fields", out JsonElement fieldsElement) ||
                        fieldsElement.ValueKind != JsonValueKind.Array ||
                        fieldsElement.GetArrayLength() == 0)
                    {
                        Console.WriteLine("Error: Invalid 'constraints' in input_descriptor.");
                        return false;
                    }

                    foreach (var field in fieldsElement.EnumerateArray())
                    {
                        if (!field.TryGetProperty("path", out JsonElement pathElement) ||
                            pathElement.ValueKind != JsonValueKind.Array ||
                            pathElement.GetArrayLength() == 0 ||
                            !field.TryGetProperty("filter", out JsonElement filterElement) ||
                            !filterElement.TryGetProperty("pattern", out JsonElement patternElement) ||
                            string.IsNullOrWhiteSpace(patternElement.GetString()))
                        {
                            Console.WriteLine("Error: Invalid 'field' in constraints.");
                            return false;
                        }
                    }
                }

                return true; // All checks passed
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Unexpected error: {ex.Message}");
                return false;
            }
        }

        public string GenerateJWTEd25519(string payload, string issuerid, Ed25519PrivateKeyParameters key)
        {

            string header = $"{{\"alg\": \"EdDSA\", \"typ\": \"JWT\", \"kid\": \"{issuerid}\"}}";
            var payloadJson = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(payload));
            var headerJson = Convert.ToBase64String(Encoding.UTF8.GetBytes(header))
                .Replace("+", "-") // Replace '+' with '-'
                .Replace("/", "_") // Replace '/' with '_'
                .TrimEnd('=');     // Remove padding characters ('=')
            var signingString = headerJson + "." + payloadJson; //$"{headerJson}.{payloadJson}";
            var payloadBytes = Encoding.UTF8.GetBytes(signingString);


            var signer = new Ed25519Signer();
            signer.Init(true, key);
            signer.BlockUpdate(payloadBytes, 0, payloadBytes.Length);


            string encodedSignature = WebEncoders.Base64UrlEncode(signer.GenerateSignature());


            return $"{headerJson}.{payloadJson}.{encodedSignature}";

            
        }

        public bool IsValidNumericDate(long numericDate)
        {
            // Define reasonable bounds for Unix timestamps
            long minValidTimestamp = 0; // January 1, 1970
            long maxValidTimestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds() + (60 * 60 * 24 * 365 * 10); // 10 years in the future

            // Check if the numericDate is within the valid range
            return numericDate >= minValidTimestamp && numericDate <= maxValidTimestamp;
        }


        public async Task<(bool isValid, string presentation_definition)> CheckPresentationDefinition(string presentation_definition_uri)
        {
            string presentation_definition = null;
            //call back uri
            using (var client = new HttpClient())
            {
                // Send the GET request
                client.DefaultRequestHeaders.Accept.Clear();
                client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                HttpResponseMessage response = await client.GetAsync(presentation_definition_uri);

                // Check if the response was successful
                response.EnsureSuccessStatusCode();

                // Read and process the response content
                var responseString = await response.Content.ReadAsStringAsync();
                presentation_definition = responseString;
                if (string.IsNullOrEmpty(responseString))
                {
                    //logs.Add(JsonSerializer.Serialize(new { message = "Fail presentation_definition", status = "400" }, new JsonSerializerOptions { WriteIndented = true }));
                    //return BadRequest();
                    return new(false, null);
                }

                //logs.Add(JsonSerializer.Serialize(new { message = presentation_definition, status = "200" }, new JsonSerializerOptions { WriteIndented = true }));
                return new(true, presentation_definition);


            }
        }

        public string IsExpectedDomain(HttpRequest request)
        {
            string domain = request.Host.Host; //Request.Host.Host;
            string filejson = null;
            filejson = "openid-credential-issuer.json";
            if (domain == "vc-testtool-test.etda.or.th")
            {
                filejson = "openid-credential-issuer-test.json";
            }
            else
            {
                filejson = "openid-credential-issuer.json";
            }

            return filejson;
        }

        public string ParseSDJWT(string vp_payload)
        {
            string vc_token = null;
            try
            {
                string payload = Base64UrlDecodeToString(vp_payload);
                Root rootObject = JsonConvert.DeserializeObject<Root>(payload);
                // SD-JWT อาจอยู่ใน verifiableCredential เหมือนเดิม
                vc_token = rootObject?.Vp?.VerifiableCredential[0]?.Trim();
            }
            catch (Exception e)
            {
                Console.WriteLine($"ParseSDJWT error: {e.Message}");
            }
            return vc_token;
        }

        public bool VerifySDJWT(string sdJwt, string publicKey, out string ErrMsg, out string kbJwt, out List<string> disclosures)
        {
            ErrMsg = null;
            kbJwt = null;
            disclosures = new List<string>();
            try
            {
                var parts = sdJwt.Split('~');

                // parts[0] = JWT (header.payload.signature)
                string jwt = parts[0];

                // parts[last] = KB-JWT (ถ้ามี)
                // parts[1..n-1] = disclosures
                for (int i = 1; i < parts.Length; i++)
                {
                    if (string.IsNullOrEmpty(parts[i])) continue;

                    // KB-JWT จะมี 3 parts เมื่อ split ด้วย '.'
                    if (parts[i].Split('.').Length == 3)
                        kbJwt = parts[i]; // Key Binding JWT
                    else
                        disclosures.Add(parts[i]); // disclosure
                }

                // Verify JWT signature
                return VerifyJWS(jwt, publicKey, out ErrMsg);
            }
            catch (Exception e)
            {
                ErrMsg = e.Message;
                return false;
            }
        }

        public Dictionary<string, object> DecodeDisclosures(List<string> disclosures)
        {
            var result = new Dictionary<string, object>();
            foreach (var d in disclosures)
            {
                try
                {
                    var json = Base64UrlDecodeToString(d);
                    var arr = JsonConvert.DeserializeObject<List<object>>(json);
                    if (arr != null && arr.Count >= 3)
                    {
                        // arr[0] = salt, arr[1] = key, arr[2] = value
                        result[arr[1].ToString()] = arr[2];
                    }
                }
                catch { }
            }
            return result;
        }

        public class SdJwtVerificationResult
        {
            public bool IsValid { get; set; }
            public string ErrorCode { get; set; }
            public string ErrorMessage { get; set; }
            public Dictionary<string, object> VerifiedClaims { get; set; } = new Dictionary<string, object>();
        }

        // SECURITY (C-04 remediation, 2026-08-08): full SD-JWT VC presentation
        // verification. Validates, in order: issuer signature, every disclosed
        // claim's digest against the signed `_sd` claim(s), the KB-JWT signature
        // against the holder key declared in `cnf`, `sd_hash` binding the KB-JWT to
        // the exact disclosure set presented, and the KB-JWT `nonce`/`aud`/`iat`.
        // Only claims whose digest was verified are ever returned. Do not surface
        // decoded disclosure values anywhere without going through this method.
        // See OID4VP-1.0-COMPLIANCE-AUDIT.md finding C-04 / Appendix B.3.6.
        public SdJwtVerificationResult VerifySDJWTPresentation(
            string sdJwtPresentation,
            string issuerPublicKey,
            string expectedNonce,
            string expectedAudience,
            string[] permittedIssuerAlgs = null)
        {
            var result = new SdJwtVerificationResult();
            try
            {
                if (string.IsNullOrWhiteSpace(sdJwtPresentation))
                {
                    result.ErrorCode = "malformed_sd_jwt";
                    return result;
                }

                bool endsWithTilde = sdJwtPresentation.EndsWith("~");
                var segments = sdJwtPresentation.Split('~');
                if (segments.Length < 1 || string.IsNullOrEmpty(segments[0]))
                {
                    result.ErrorCode = "malformed_sd_jwt";
                    return result;
                }

                string issuerJwt = segments[0];
                string kbJwt = null;
                var disclosureParts = new List<string>();

                for (int i = 1; i < segments.Length; i++)
                {
                    if (string.IsNullOrEmpty(segments[i])) continue;
                    bool isLastSegment = i == segments.Length - 1;
                    if (isLastSegment && !endsWithTilde && segments[i].Split('.').Length == 3)
                        kbJwt = segments[i];
                    else
                        disclosureParts.Add(segments[i]);
                }

                // 1. Issuer signature over the issuer-signed JWT. permittedIssuerAlgs
                // (Phase 1 item 6 / H-05) is only applied here, not to the KB-JWT
                // below — the holder's Key Binding key algorithm is a separate axis
                // from the credential issuance format's configured AlgValues.
                if (!VerifyJWS(issuerJwt, issuerPublicKey, out string issuerErr, permittedIssuerAlgs))
                {
                    result.ErrorCode = "invalid_issuer_signature";
                    result.ErrorMessage = issuerErr;
                    return result;
                }

                var issuerJwtParts = issuerJwt.Split('.');
                if (issuerJwtParts.Length != 3)
                {
                    result.ErrorCode = "malformed_sd_jwt";
                    return result;
                }
                string payloadJson = Base64UrlDecodeToString(issuerJwtParts[1]);
                using var payloadDoc = JsonDocument.Parse(payloadJson);
                JsonElement root = payloadDoc.RootElement;

                // 1b. Credential time validity (Phase 1 item 8 / H-04) — reject a
                // credential that is expired or not yet valid per its own nbf/exp.
                long? credNbf = root.TryGetProperty("nbf", out var nbfEl) && nbfEl.TryGetInt64(out long nbfVal) ? nbfVal : (long?)null;
                long? credExp = root.TryGetProperty("exp", out var expEl) && expEl.TryGetInt64(out long expVal) ? expVal : (long?)null;
                if (!IsCredentialTimeValid(credNbf, credExp, out string timeErr))
                {
                    result.ErrorCode = timeErr;
                    result.ErrorMessage = "Credential is expired or not yet valid";
                    return result;
                }

                // 2. Holder confirmation key is required — this deployment does not
                // accept SD-JWT VCs that cannot prove holder binding.
                // FIX (H-01 follow-up, 2026-08-11): this used to always treat
                // cnf.jwk.x as a raw Ed25519/OKP public key, so an EC/P-256
                // cnf.jwk (kty="EC", crv="P-256", separate x/y coordinates) was
                // silently reduced to just its x coordinate and passed to
                // VerifyJWS, which requires a {"crv","x","y"} JSON blob to take
                // its ES256 path (see VerifyJWS's Es256KeyMaterial dispatch
                // above) — that mismatch made every EC/P-256 holder key fail
                // KB-JWT signature verification. Now branches on cnf.jwk.kty/crv
                // and builds the JSON blob VerifyJWS expects for EC/P-256 keys,
                // keeping the raw-x path for Ed25519/OKP keys unchanged.
                if (!root.TryGetProperty("cnf", out var cnfElement) ||
                    !cnfElement.TryGetProperty("jwk", out var jwkElement) ||
                    !jwkElement.TryGetProperty("x", out var xElement) ||
                    string.IsNullOrEmpty(xElement.GetString()))
                {
                    result.ErrorCode = "missing_holder_binding_key";
                    result.ErrorMessage = "Credential has no usable cnf.jwk.x";
                    return result;
                }

                string holderKty = jwkElement.TryGetProperty("kty", out var ktyEl) ? ktyEl.GetString() : null;
                string holderCrv = jwkElement.TryGetProperty("crv", out var crvEl) ? crvEl.GetString() : null;
                string holderPublicKey;
                if (string.Equals(holderKty, "EC", StringComparison.OrdinalIgnoreCase) &&
                    string.Equals(holderCrv, "P-256", StringComparison.OrdinalIgnoreCase))
                {
                    if (!jwkElement.TryGetProperty("y", out var yElement) || string.IsNullOrEmpty(yElement.GetString()))
                    {
                        result.ErrorCode = "missing_holder_binding_key";
                        result.ErrorMessage = "Credential cnf.jwk is EC/P-256 but has no y coordinate";
                        return result;
                    }
                    holderPublicKey = JsonConvert.SerializeObject(new
                    {
                        crv = "P-256",
                        x = xElement.GetString(),
                        y = yElement.GetString()
                    });
                }
                else
                {
                    // Ed25519/OKP holder key — raw base64url x value, as before.
                    holderPublicKey = xElement.GetString();
                }

                // 3. Every disclosed claim's digest must be present in the signed _sd
                string sdAlg = root.TryGetProperty("_sd_alg", out var algEl) && !string.IsNullOrEmpty(algEl.GetString())
                    ? algEl.GetString()
                    : "sha-256";

                var validDigests = new HashSet<string>(StringComparer.Ordinal);
                CollectSdDigests(root, validDigests);

                var verifiedClaims = new Dictionary<string, object>();
                foreach (var disclosure in disclosureParts)
                {
                    string digest = ComputeHashBase64Url(disclosure, sdAlg);
                    if (!validDigests.Contains(digest))
                    {
                        result.ErrorCode = "disclosure_digest_mismatch";
                        result.ErrorMessage = "A disclosed claim was not found in the signed credential's _sd digests";
                        return result;
                    }

                    string disclosureJson = Base64UrlDecodeToString(disclosure);
                    var arr = JsonConvert.DeserializeObject<List<object>>(disclosureJson);
                    if (arr != null && arr.Count == 3)
                    {
                        // [salt, claimName, claimValue] — object-property disclosure
                        verifiedClaims[arr[1].ToString()] = arr[2];
                    }
                    // 2-element disclosures ([salt, value], used for array elements) are
                    // digest-verified above but not surfaced as top-level claims here.
                }

                // 4. KB-JWT is required once a holder key is declared
                if (string.IsNullOrEmpty(kbJwt))
                {
                    result.ErrorCode = "missing_kb_jwt";
                    result.ErrorMessage = "Key Binding JWT is required but was not present";
                    return result;
                }

                if (!VerifyJWS(kbJwt, holderPublicKey, out string kbErr))
                {
                    result.ErrorCode = "invalid_kb_jwt_signature";
                    result.ErrorMessage = kbErr;
                    return result;
                }

                var kbParts = kbJwt.Split('.');
                if (kbParts.Length != 3)
                {
                    result.ErrorCode = "malformed_kb_jwt";
                    return result;
                }
                string kbPayloadJson = Base64UrlDecodeToString(kbParts[1]);
                using var kbDoc = JsonDocument.Parse(kbPayloadJson);
                JsonElement kbRoot = kbDoc.RootElement;

                // 5. sd_hash — binds the KB-JWT to exactly this issuer-JWT + disclosure set
                string signedPart = issuerJwt + "~";
                foreach (var d in disclosureParts) signedPart += d + "~";
                string computedSdHash = ComputeHashBase64Url(signedPart, sdAlg);
                string claimedSdHash = kbRoot.TryGetProperty("sd_hash", out var sdHashEl) ? sdHashEl.GetString() : null;
                if (string.IsNullOrEmpty(claimedSdHash) ||
                    !CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(claimedSdHash), Encoding.UTF8.GetBytes(computedSdHash)))
                {
                    result.ErrorCode = "sd_hash_mismatch";
                    result.ErrorMessage = "KB-JWT sd_hash does not match the presented issuer-JWT + disclosure set";
                    return result;
                }

                // 6. nonce — must match the nonce issued for this session (replay protection)
                string kbNonce = kbRoot.TryGetProperty("nonce", out var nonceEl) ? nonceEl.GetString() : null;
                if (string.IsNullOrEmpty(expectedNonce) || !string.Equals(kbNonce, expectedNonce, StringComparison.Ordinal))
                {
                    result.ErrorCode = "nonce_mismatch";
                    result.ErrorMessage = "KB-JWT nonce does not match the session nonce";
                    return result;
                }

                // 7. aud — must match this Verifier's exact client_id
                string kbAud = kbRoot.TryGetProperty("aud", out var audEl) ? audEl.GetString() : null;
                if (string.IsNullOrEmpty(expectedAudience) || !string.Equals(kbAud, expectedAudience, StringComparison.Ordinal))
                {
                    result.ErrorCode = "audience_mismatch";
                    result.ErrorMessage = "KB-JWT aud does not match this Verifier's client_id";
                    return result;
                }

                // 8. iat freshness — reject stale Key Binding JWTs
                if (!kbRoot.TryGetProperty("iat", out var iatEl) || !iatEl.TryGetInt64(out long kbIat))
                {
                    result.ErrorCode = "missing_kb_jwt_iat";
                    return result;
                }
                long nowUnix = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                const long maxSkewSeconds = 300; // 5 minutes
                if (Math.Abs(nowUnix - kbIat) > maxSkewSeconds)
                {
                    result.ErrorCode = "kb_jwt_not_fresh";
                    result.ErrorMessage = "Key Binding JWT iat is too old or in the future";
                    return result;
                }

                result.IsValid = true;
                result.VerifiedClaims = verifiedClaims;
                return result;
            }
            catch (Exception e)
            {
                result.ErrorCode = "sd_jwt_verification_error";
                result.ErrorMessage = e.Message;
                return result;
            }
        }

        // Recursively collect every digest listed in any "_sd" array anywhere in the
        // credential payload (top-level and nested objects/arrays), per SD-JWT's
        // selective disclosure structure.
        private void CollectSdDigests(JsonElement element, HashSet<string> digests)
        {
            if (element.ValueKind == JsonValueKind.Object)
            {
                foreach (var prop in element.EnumerateObject())
                {
                    if (prop.NameEquals("_sd") && prop.Value.ValueKind == JsonValueKind.Array)
                    {
                        foreach (var d in prop.Value.EnumerateArray())
                        {
                            if (d.ValueKind == JsonValueKind.String)
                                digests.Add(d.GetString());
                        }
                    }
                    else
                    {
                        CollectSdDigests(prop.Value, digests);
                    }
                }
            }
            else if (element.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in element.EnumerateArray())
                {
                    CollectSdDigests(item, digests);
                }
            }
        }

        // digest = base64url( hash( ASCII(base64url-encoded-input) ) ), per the
        // SD-JWT disclosure digest / sd_hash calculation rules.
        private string ComputeHashBase64Url(string asciiInput, string alg)
        {
            byte[] inputBytes = Encoding.ASCII.GetBytes(asciiInput);
            byte[] hash = alg?.ToLowerInvariant() switch
            {
                "sha-256" or "sha256" => SHA256.HashData(inputBytes),
                "sha-384" or "sha384" => SHA384.HashData(inputBytes),
                "sha-512" or "sha512" => SHA512.HashData(inputBytes),
                _ => throw new NotSupportedException($"Unsupported _sd_alg: {alg}")
            };
            return WebEncoders.Base64UrlEncode(hash);
        }

        // FIX (Phase 1 item 7 / C-02, 2026-08-09): the jwt_vc_json presentation path
        // never checked that the outer VP-JWT's own `nonce`/`aud` claims matched this
        // session — only the SD-JWT path's KB-JWT got that check. Without this, a
        // presentation JWT signed for a different session/verifier could be replayed
        // here as long as its own signature was valid.
        // See OID4VP-1.0-COMPLIANCE-AUDIT.md Phase 1 item 7 / C-02.
        public bool ValidateVpNonceAndAudience(string base64UrlPayload, string expectedNonce, string expectedAudience, out string errorCode)
        {
            errorCode = null;
            try
            {
                string payloadJson = Base64UrlDecodeToString(base64UrlPayload);
                using JsonDocument doc = JsonDocument.Parse(payloadJson);
                JsonElement root = doc.RootElement;

                string nonce = root.TryGetProperty("nonce", out var nonceEl) ? nonceEl.GetString() : null;
                if (string.IsNullOrEmpty(expectedNonce) || !string.Equals(nonce, expectedNonce, StringComparison.Ordinal))
                {
                    errorCode = "nonce_mismatch";
                    return false;
                }

                bool audMatches = false;
                if (root.TryGetProperty("aud", out var audEl))
                {
                    if (audEl.ValueKind == JsonValueKind.String)
                    {
                        audMatches = string.Equals(audEl.GetString(), expectedAudience, StringComparison.Ordinal);
                    }
                    else if (audEl.ValueKind == JsonValueKind.Array)
                    {
                        foreach (var item in audEl.EnumerateArray())
                        {
                            if (item.ValueKind == JsonValueKind.String &&
                                string.Equals(item.GetString(), expectedAudience, StringComparison.Ordinal))
                            {
                                audMatches = true;
                                break;
                            }
                        }
                    }
                }
                if (string.IsNullOrEmpty(expectedAudience) || !audMatches)
                {
                    errorCode = "audience_mismatch";
                    return false;
                }

                return true;
            }
            catch (Exception)
            {
                errorCode = "malformed_vp_payload";
                return false;
            }
        }

        // FIX (Phase 1 item 8 / H-04, 2026-08-09): checks that the credential actually
        // returned matches what this session's DCQL query asked for (format +
        // type/vct), instead of accepting whatever the Wallet sent back and only
        // using it to pick a display route. Fails open (returns true) when there is
        // no stored query to check against, so sessions created before this column
        // existed don't start failing.
        // See OID4VP-1.0-COMPLIANCE-AUDIT.md Phase 1 item 8 / H-04.
        public bool ValidateAgainstDcqlQuery(string dcqlQueryJson, string actualFormat, string actualTypeOrVct, out string errorCode)
        {
            errorCode = null;
            if (string.IsNullOrWhiteSpace(dcqlQueryJson))
            {
                return true;
            }
            try
            {
                using JsonDocument doc = JsonDocument.Parse(dcqlQueryJson);
                if (!doc.RootElement.TryGetProperty("credentials", out var credentials) || credentials.GetArrayLength() == 0)
                {
                    errorCode = "dcql_query_empty";
                    return false;
                }
                // JsonElement has no int indexer (unlike Newtonsoft's JToken) — use
                // EnumerateArray() instead of `credentials[0]`.
                var cred = credentials.EnumerateArray().First();
                string expectedFormat = cred.TryGetProperty("format", out var fmtEl) ? fmtEl.GetString() : null;
                if (!string.IsNullOrEmpty(expectedFormat) && !string.Equals(expectedFormat, actualFormat, StringComparison.OrdinalIgnoreCase))
                {
                    errorCode = "unexpected_credential_format";
                    return false;
                }

                if (cred.TryGetProperty("meta", out var meta))
                {
                    string[] expectedValues = null;
                    if (meta.TryGetProperty("type_values", out var typeValuesEl) && typeValuesEl.ValueKind == JsonValueKind.Array)
                    {
                        expectedValues = typeValuesEl.EnumerateArray()
                            .Select(v => v.ValueKind == JsonValueKind.String ? v.GetString() : null)
                            .Where(v => v != null).ToArray();
                    }
                    else if (meta.TryGetProperty("vct_values", out var vctValuesEl) && vctValuesEl.ValueKind == JsonValueKind.Array)
                    {
                        expectedValues = vctValuesEl.EnumerateArray()
                            .Select(v => v.ValueKind == JsonValueKind.String ? v.GetString() : null)
                            .Where(v => v != null).ToArray();
                    }

                    if (expectedValues != null && expectedValues.Length > 0)
                    {
                        bool matches = !string.IsNullOrEmpty(actualTypeOrVct) &&
                            expectedValues.Any(v => string.Equals(v, actualTypeOrVct, StringComparison.Ordinal));
                        if (!matches)
                        {
                            errorCode = "unexpected_credential_type";
                            return false;
                        }
                    }

                    // FIX (H-01 follow-up / NFC-mdoc support, 2026-08-11): mso_mdoc
                    // uses `doctype_value` (a single string, OpenID4VP Appendix
                    // B.2.3) rather than type_values/vct_values — compare the
                    // mdoc's actual docType against it the same way.
                    if (string.Equals(actualFormat, "mso_mdoc", StringComparison.OrdinalIgnoreCase) &&
                        meta.TryGetProperty("doctype_value", out var doctypeValueEl))
                    {
                        string expectedDoctype = doctypeValueEl.GetString();
                        if (!string.IsNullOrEmpty(expectedDoctype) &&
                            !string.Equals(expectedDoctype, actualTypeOrVct, StringComparison.Ordinal))
                        {
                            errorCode = "unexpected_credential_type";
                            return false;
                        }
                    }
                }

                return true;
            }
            catch (Exception)
            {
                errorCode = "malformed_dcql_query";
                return false;
            }
        }

        // FIX (Phase 1 item 8 / H-04, 2026-08-09): rejects a credential whose own
        // nbf/exp claims say it is not currently valid. Missing claims are treated as
        // "no constraint" rather than a failure, since not every issuer sets both.
        // See OID4VP-1.0-COMPLIANCE-AUDIT.md Phase 1 item 8 / H-04.
        public bool IsCredentialTimeValid(long? nbf, long? exp, out string errorCode)
        {
            errorCode = null;
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            const long skewSeconds = 60;
            if (exp.HasValue && now > exp.Value + skewSeconds)
            {
                errorCode = "credential_expired";
                return false;
            }
            if (nbf.HasValue && now < nbf.Value - skewSeconds)
            {
                errorCode = "credential_not_yet_valid";
                return false;
            }
            return true;
        }

        public string GetVctFromSdJwt(string vpToken)
        {
            //VCService vcSev = new VCService();
            try
            {
                // 1. แยก JWT ออกจาก disclosures
                string jwt = vpToken.Split('~')[0];

                // 2. แยก header.payload.signature
                string[] jwtParts = jwt.Split('.');
                if (jwtParts.Length < 2)
                    return null;

                // 3. Decode payload
                string payloadJson = Base64UrlDecodeToString(jwtParts[1]);

                // 4. อ่าน vct
                using JsonDocument doc = JsonDocument.Parse(payloadJson);
                if (doc.RootElement.TryGetProperty("vct", out JsonElement vctElement))
                {
                    string vct = vctElement.GetString();
                    return vct;
                }

                return null;
            }
            catch (Exception ex)
            {
                //logger.Error($"GetVctFromSdJwt error: {ex.Message}");
                return null;
            }
        }
        public object BuildDcqlQuery(Dbdocumenttype docType, HttpRequest Request)
        {
            var vcTypes = JsonConvert.DeserializeObject<string[]>(docType.VcType)
                          ?? throw new InvalidOperationException($"VcType invalid: {docType.VcType}");

            string format = docType.Format?.ToLower();
            string issuerBaseUrl = Environment.GetEnvironmentVariable("ISSUER_BASE_URL")
              ?? Environment.GetEnvironmentVariable("INTERNAL_BASE_URL")
              ?? Environment.GetEnvironmentVariable("IssuerUrl")
              ?? $"{Request.Scheme}://{Request.Host}";
            if (format == "dc+sd-jwt")
            {
                var claimPaths = GetClaimsByDocType(docType.DocType);
                // SD-JWT ใช้ vct_values — เอา type สุดท้าย เช่น "TranscriptCredential"
                return new
                {
                    credentials = new[]
                    {
                        new
                        {
                            id     = docType.DocType,
                            format = format,
                            meta   = new
                            {
                                vct_values = new[] { issuerBaseUrl + "/credentials/" + docType.Endpoint }
                            },
                            claims = claimPaths
                        }
                    }
                };
            }

            // FIX (H-01 follow-up / NFC-mdoc support, 2026-08-11): mso_mdoc
            // (ISO/IEC 18013-5 mdoc, OpenID4VP Appendix B.2) uses a single
            // `doctype_value` string in `meta` (Appendix B.2.3) rather than
            // type_values/vct_values. Reuses the existing VcType column (already
            // JSON-array-of-strings) and takes its first element as the ISO
            // doctype identifier, matching how VcType is otherwise used for
            // jwt_vc_json's type_values below. `claims` is intentionally omitted
            // (requests the whole credential) — mdoc's Claims Query paths are
            // [NameSpace, DataElementIdentifier] pairs, a different shape from
            // the JSON-path claims this deployment's existing document types use
            // (GetClaimsByDocType), and no mdoc document type has been configured
            // with claim-level restrictions yet.
            // See OID4VP-1.0-COMPLIANCE-AUDIT.md finding H-01.
            if (format == "mso_mdoc")
            {
                string doctypeValue = vcTypes.Length > 0 ? vcTypes[0] : docType.DocType;
                return new
                {
                    credentials = new[]
                    {
                        new
                        {
                            id     = docType.DocType,
                            format = format,
                            meta   = new
                            {
                                doctype_value = doctypeValue
                            }
                        }
                    }
                };
            }

            // FIX (H-02, 2026-08-09): OpenID4VP requires type_values to be a
            // non-empty array of non-empty string arrays (Appendix B.1.1) — each
            // inner array is one full acceptable credential `type`/`@type` set, not
            // a single type string. This used to emit `["IDCardCredential"]`
            // (missing "VerifiableCredential" and wrapped one level too shallow);
            // now emits `[["VerifiableCredential","IDCardCredential"]]`.
            // See OID4VP-1.0-COMPLIANCE-AUDIT.md finding H-02.
            return new
            {
                credentials = new[]
                {
                    new
                    {
                        id     = docType.DocType,
                        format = format,
                        meta   = new
                        {
                            type_values = new[] { vcTypes }
                        }
                    }
                }
            };
        }

        public object BuildDcqlQuery(string type_id, HttpRequest Request)
        {
            // แนะนำ: ควร inject DBService ผ่าน constructor แทนการ new ตรงนี้
            // (ตอนนี้ new ตรง ๆ ทำงานได้ แต่ผูก dependency แน่นเกินไป ทดสอบยาก
            //  และอาจพลาด connection string / DI configuration ที่ควรมาจาก IConfiguration)
            DBService dbServ = new DBService();
            Dbdocumenttype dbType = dbServ.GetRequestByDocType(type_id);

            // เพิ่ม null check ให้ครบ — ไม่งั้น compile ไม่ผ่าน (CS0161)
            if (dbType == null)
            {
                throw new InvalidOperationException($"ไม่พบ document type: {type_id} ใน database");
            }

            var vcTypes = JsonConvert.DeserializeObject<string[]>(dbType.VcType)
                      ?? throw new InvalidOperationException($"VcType invalid: {dbType.VcType}");

            // แก้จาก dbType.DocType เป็น dbType.Format — เดิมใช้ผิด field
            // ทำให้เงื่อนไข dc+sd-jwt ด้านล่างไม่มีทาง true ได้เลย
            string format = dbType.Format?.ToLower();

            string issuerBaseUrl = Environment.GetEnvironmentVariable("ISSUER_BASE_URL")
              ?? Environment.GetEnvironmentVariable("INTERNAL_BASE_URL")
              ?? Environment.GetEnvironmentVariable("IssuerUrl")
              ?? $"{Request.Scheme}://{Request.Host}";

            if (format == "dc+sd-jwt")
            {
                var claimPaths = GetClaimsByDocType(dbType.DocType);
                // SD-JWT ใช้ vct_values — เอา type สุดท้าย เช่น "TranscriptCredential"
                return new
                {
                    credentials = new[]
                    {
                        new
                        {
                            id     = dbType.DocType,
                            format = format,
                            meta   = new
                            {
                                vct_values = new[] { issuerBaseUrl + "/credentials/" + dbType.Endpoint }
                            },
                            claims = claimPaths
                        }
                    }
                };
            }

            // jwt_vc_json ใช้ type_values
            return new
            {
                credentials = new[]
                {
                    new
                    {
                        id     = dbType.DocType,
                        format = format,
                        meta   = new
                        {
                            // FIX (H-02, 2026-08-09): see the other BuildDcqlQuery
                            // overload above — type_values must be an array of
                            // string arrays, not an array of one string.
                            type_values = new[] { vcTypes }
                        },
                        // เพิ่มบรรทัดนี้ — เดิมไม่มี claims เลยใน branch นี้
                        claims = GetClaimsByDocType(dbType.DocType)
                    }
                }
            };
        }

        private object[] GetClaimsByDocType(string docType)
        {
            return docType?.ToLower() switch
            {
                // ✅ IDCard
                "idcard_credential" => new object[]
                {
                    new { path = new[] { "id_number"    } },
                    new { path = new[] { "full_name"    } },
                    new { path = new[] { "birthdate"    } },
                    new { path = new[] { "expiry_date"  } },
                    //new { path = new[] { "religion"     } }
                   // new { path = new[] { "photo"        } }
                },

                // ✅ Transcript
                "transcript_credential" => new object[]
                {
                   // new { path = new[] { "student_id"   } },
                    new { path = new[] { "full_name"    } },
                    new { path = new[] { "degree"       } },
                    new { path = new[] { "institution_name" } },
                    new { path = new[] { "faculty"      } },
                    new { path = new[] { "gpa"          } },
                    new { path = new[] { "graduation_date" } }
                },

                // ✅ Driver License
                // FIX (claim-name mismatch, 2026-08-19): these paths previously used
                // made-up flat names (license_number/givenname/familyname/birthdate/
                // license_class/portrait, and before that full_name/license_type/photo)
                // that do not match any claim this Issuer actually discloses. A dc+sd-jwt
                // DCQL `claims` entry must name the exact top-level disclosure keys in the
                // credential (OpenID4VP §6.1 claims_query / DCQL processing rules, §6.4) —
                // a Wallet cannot satisfy a query for claims that don't exist in the
                // credential. Renamed to match this Issuer's 9 disclosures exactly:
                // family_name, given_name, birth_date, document_number, issue_date,
                // expiry_date, resident_address, driving_privileges, portrait.
                "driverlicense_credential" => new object[]
                {
                    new { path = new[] { "family_name"        } },
                    new { path = new[] { "given_name"         } },
                    new { path = new[] { "birth_date"         } },
                    new { path = new[] { "document_number"    } },
                    new { path = new[] { "issue_date"         } },
                    new { path = new[] { "expiry_date"        } },
                    new { path = new[] { "resident_address"   } },
                    new { path = new[] { "driving_privileges" } },
                    //new { path = new[] { "portrait"           } }
                },

                // Default — ไม่รู้จัก docType ส่ง empty (ขอทั้งหมด)
                _ => Array.Empty<object>()
            };
        }

        //public string getProofByNonce(string proof)
        //{
        //    DBService dbServ = new DBService();
        //    string jwt = proof;
        //    string[] parts = jwt.Split('.');

        //    // Decode the header and payload
        //    string payload = Base64UrlDecodeToString(parts[1]);
        //    using JsonDocument doc = JsonDocument.Parse(payload);
        //    string nonce = doc.RootElement.GetProperty("nonce").GetString();
        //    string id = dbServ.GetRegisterId(nonce);

        //    return id;
        //}


        //public JsonResult GenerateTranscriptVC(string issuerid, string walletid) 
        //{

        //    _JwtPayloadModel model = new _JwtPayloadModel();
        //    var token = new JsonResult(new { Ok = "" });

        //    try
        //    {

        //        model.issuer.id = issuerid; //GetLegalEntityDID();

        //        model.issuer.name = "Chulalongkorn University";//UniversityName;

        //        Guid newGuid = Guid.NewGuid();

        //        model.id = model.issuer.id;
        //        model.id = $"urn:uuid:{newGuid}";
        //        model.issuanceDate = DateTime.Now.ToString("yyyy-MM-ddTHH:mm:ss.fffffffK");


        //        vcModel payload = new vcModel();
        //        DateTime currentTime = DateTime.UtcNow;
        //        long unixTime = ((DateTimeOffset)currentTime).ToUnixTimeSeconds();
        //        DateTime end = currentTime.AddMinutes(30);
        //        long endTime = ((DateTimeOffset)end).ToUnixTimeSeconds();
        //        payload.iss = issuerid; // "did:key:z6MkjoRhq1jSNJdLiruSXrFFxagqrztZaXHqHGUTKJbcNywp";
        //        payload.sub = walletid; //wallet id
        //        payload.vc = model;
        //        payload.jti = $"urn:uuid:{newGuid}";
        //        payload.iat = unixTime;
        //        payload.nbf = unixTime;// 1730005968; // endTime;
        //        token = new JsonResult(payload);
        //        var options = new JsonSerializerOptions
        //        {
        //            WriteIndented = true,
        //        };


        //        //add details
        //        model.credentialSubject.id = walletid;//wallet id

        //        DocumentContextDetail context = new DocumentContextDetail();
        //        context.Type = "DigitalDocument";
        //        context.Identifiers.Add(new Identifier()
        //        {
        //            Type = "PropertyValue",
        //            Name = "OID",
        //            Value = "2.16.764.1.4.1.1.8.1.1"
        //        });
        //        context.SchemaVersion = "1.0";
        //        context.Author = new Author();
        //        context.Author.Type = "Organization";
        //        context.Author.Name = "ETDA";
        //        payload.vc.credentialSubject.documentContext = context;

        //        TedaDocumentInformation docInform = new TedaDocumentInformation();
        //        docInform.Type = "DigitalDocument";
        //        docInform.Identifier = new IdentifierDocument();
        //        docInform.Identifier.Type = "PropertyValue";
        //        docInform.Identifier.PropertyID = "Transcript ID";
        //        docInform.Identifier.Value = "123456";
        //        docInform.Name = "Transcript Name";
        //        docInform.AdditionalType = "รหัสระบุประเภทเอกสาร";
        //        docInform.EducationalUse = "วัตถุประสงค์";
        //        docInform.DatePublished = "Issue Date";
        //        docInform.Description = "Description of the document";

        //        docInform.InLanguage = new Language();
        //        docInform.InLanguage.Name = "Thai";
        //        docInform.InLanguage.Type = "Language";
        //        docInform.InLanguage.AlternateName = "th";
        //        payload.vc.credentialSubject.tedadocumentInformation = docInform;


        //        TedaStudent item = new TedaStudent();
        //        item.Type = "Person";
        //        item.Identifier = new Identifier();
        //        item.Identifier.Type = "PropertyValue";
        //        item.Identifier.Name = "StudenID";
        //        item.Identifier.Value = "123456";

        //        item.HonorificPrefix = "นาย";
        //        item.GivenName = "ทดสอบ";
        //        item.FamilyName = "เอกสารดิจิตัล";
        //        item.Gender = "1";
        //        item.BirthDate = "2015-01-30";
        //        item.Nationality = "TH";

        //        ResidentCountryOrTerritory res = new ResidentCountryOrTerritory();
        //        res.Type = "PostalAddress";
        //        res.addressCountry = "TH";
        //        item.ResidentCountryOrTerritory = res;
        //        item.Image = "/examples/jvanzweden_s.jpg";
        //        item.FacultyName = "คณะวิศวกรรมศาสตร์";

        //        ProgramContext program = new ProgramContext();
        //        program.Type = "EducationalOccupationalProgram";
        //        program.Identifier = new Identifier();
        //        program.Identifier.Type = "PropertyValue";
        //        program.Identifier.Name = "ProgramID";
        //        program.Identifier.Value = "123456";
        //        program.Name = "ชื่อหลักสูตร";
        //        program.ProgramType.Add(new ProgramType()
        //        {
        //            Type = "DefinedTerm",
        //            Name = "กลุ่มสาขาหลัก",
        //            TermCode = "Major"

        //        });
        //        program.EndDate = "2023-01-01";
        //        program.NumberOfCredits = 8;
        //        program.EducationalCredentialAwarded = "เกียรตินิยมอันดับ 1";

        //        program.ProgramPrerequisites = new ProgramPrerequisites();
        //        program.ProgramPrerequisites.Type = "EducationalOccupationalCredential";
        //        program.ProgramPrerequisites.EducationalLevel = "ป.ตรี";
        //        program.ProgramPrerequisites.RecognizedBy = "สถาบันการศึกษาก่อนหน้า";

        //        item.ProgramContext = program;
        //        payload.vc.credentialSubject.tedastudent = item;


        //        AcademicSummaryDetails academicSummary = new AcademicSummaryDetails();
        //        academicSummary.Type = "teda:AcademicSummary";

        //        SemesterSummary summary = new SemesterSummary();
        //        summary.Type = "teda:semester";
        //        summary.EducationTypeSystem = "ทวิภาค";
        //        summary.SemesterStatus = "ปกติ";
        //        summary.SemesterName = "ภาคการศึกษา1";
        //        summary.Year = "2023";
        //        summary.SemesterCreditValue = 60;
        //        summary.SemesterCreditEarned = 45;
        //        summary.SemesterCreditCalculated = 46;
        //        summary.SemesterPointEarned = 120;
        //        summary.SemesterGPA = 3.8;
        //        summary.SemesterGPAX = 3.8;
        //        summary.Remark = "";
        //        payload.vc.credentialSubject.academicSummary = academicSummary;
        //        payload.vc.credentialSubject.academicSummary.SemesterSummaries.Add(summary);


        //        OrganizationDetails orgEdu = new OrganizationDetails();
        //        orgEdu.Type = "EducationalOrganization";
        //        orgEdu.Identifier = new Identifier();
        //        orgEdu.Identifier.Type = "PropertyValue";
        //        orgEdu.Identifier.Name = "OrganizationID";
        //        orgEdu.Identifier.Value = "123456";
        //        orgEdu.Name = "University Name";
        //        orgEdu.SchoolLevel = "ปริญญาตรี";
        //        orgEdu.Address = new PostalAddress();
        //        orgEdu.Address.Type = "PostalAddress";
        //        orgEdu.Address.StreetAddress = "Street Address";
        //        orgEdu.Address.AddressLocality = "City";
        //        orgEdu.Address.AddressRegion = "State/Region";
        //        orgEdu.Address.PostalCode = "Postal Code";
        //        orgEdu.Address.AddressCountry = "Country";

        //        orgEdu.SubOrganization = new SubOrganization();
        //        orgEdu.SubOrganization.Identifier = new Identifier();
        //        orgEdu.SubOrganization.Identifier.Type = "PropertyValue";
        //        orgEdu.SubOrganization.Identifier.Name = "CampusID";
        //        orgEdu.SubOrganization.Identifier.Value = "123456";
        //        orgEdu.SubOrganization.Name = "Campu Name";
        //        orgEdu.SubOrganization.Address = new PostalAddress();
        //        orgEdu.SubOrganization.Address.Type = "PostalAddress";
        //        orgEdu.SubOrganization.Address.StreetAddress = "Street Address";
        //        orgEdu.SubOrganization.Address.AddressLocality = "City";
        //        orgEdu.SubOrganization.Address.AddressRegion = "State/Region";
        //        orgEdu.SubOrganization.Address.PostalCode = "Postal Code";
        //        orgEdu.SubOrganization.Address.AddressCountry = "Country";

        //        orgEdu.Registrar = new Registrar();
        //        orgEdu.Registrar.Type = "Person";
        //        orgEdu.Registrar.Identifier = new Identifier();
        //        orgEdu.Registrar.Identifier.Type = "PropertyValue";
        //        orgEdu.Registrar.Identifier.Name = "Registrar ID";
        //        orgEdu.Registrar.Identifier.Value = "123456";

        //        orgEdu.Registrar.JobTitle = "นายทะเบียน";
        //        orgEdu.Registrar.HonorificPrefix = "นางสาว";
        //        orgEdu.Registrar.HonorificPrefix = "นางสาว";
        //        orgEdu.Registrar.Name = "ชื่อ-นามสกุลนายทะเบียน";
        //        orgEdu.Registrar.Email = "email";

        //        CourseList courseList = new CourseList();
        //        Course course = new Course();
        //        course.Type = "Course";
        //        course.CourseCode = "Course Code";
        //        course.Name = "Computer Science 101";
        //        course.AdditionalType = "หมวดวิชาเทคโนโลยีสารสนเทศ";
        //        course.Description = "Course Description";
        //        course.NumberOfCredits = 1;
        //        course.CreditEarned = 3;
        //        course.Grade = 4;
        //        course.GradeText = "A";
        //        course.PointEarned = 12;
        //        courseList.ItemList.Add(course);


        //        CredentialStatus credentialStatus = new CredentialStatus();
        //        credentialStatus.Id = "https://example.com/credentials/status/3#94567";
        //        credentialStatus.Type = "BitstringStatusListEntry";
        //        credentialStatus.StatusPurpose = "revocation";
        //        credentialStatus.StatusListIndex = "94567";
        //        credentialStatus.StatusListCredential = "https://example.com/credentials/status/3";
        //        payload.vc.credentialStatus = credentialStatus;

        //        CredentialSchema credentialSchema = new CredentialSchema();
        //        credentialSchema.id = "https://schemas-uat.teda.th/teda/teda-objects/common/verified-credential/transcript/-/blob/main/schema/transcript_vc_schema.json";
        //        credentialSchema.type = "JsonSchema";
        //        payload.vc.credentialSchema = credentialSchema;

        //        payload.vc.credentialSubject.educationalOrganization = orgEdu;

        //        var writeToken = JsonSerializer.Serialize(model, options);
        //        //**Database.Write(client, "VC", writeToken);


        //    }
        //    catch (Exception e)
        //    {
        //        //
        //        token = new JsonResult(new { error = e.Message})
        //        {
        //            StatusCode = 400
        //        };
        //    }

        //    return token;

        //}


        //public JsonResult GenerateIDCardVC(string issuerid, string walletid)
        //{

        //    _JwtPayloadModel model = new _JwtPayloadModel();
        //    var token = new JsonResult(new { Ok = "" });

        //    try
        //    {

        //        model.issuer.id = issuerid; //GetLegalEntityDID();

        //        model.issuer.name = "Department Of Provincial Administration";//UniversityName;

        //        Guid newGuid = Guid.NewGuid();

        //        model.id = model.issuer.id;
        //        model.id = $"urn:uuid:{newGuid}";
        //        model.issuanceDate = DateTime.Now.ToString("yyyy-MM-ddTHH:mm:ss.fffffffK");


        //        vcModel payload = new vcModel();
        //        DateTime currentTime = DateTime.UtcNow;
        //        long unixTime = ((DateTimeOffset)currentTime).ToUnixTimeSeconds();
        //        DateTime end = currentTime.AddMinutes(30);
        //        long endTime = ((DateTimeOffset)end).ToUnixTimeSeconds();
        //        payload.iss = issuerid; // "did:key:z6MkjoRhq1jSNJdLiruSXrFFxagqrztZaXHqHGUTKJbcNywp";
        //        payload.sub = walletid; //wallet id
        //        payload.vc = model;
        //        payload.jti = $"urn:uuid:{newGuid}";
        //        payload.iat = unixTime;
        //        payload.nbf = unixTime;// 1730005968; // endTime;
        //        token = new JsonResult(payload);
        //        var options = new JsonSerializerOptions
        //        {
        //            WriteIndented = true,
        //        };


        //        //add details
        //        model.credentialSubject.id = walletid;//wallet id

        //        DocumentContextDetail context = new DocumentContextDetail();
        //        context.Type = "DigitalDocument";
        //        context.Identifiers.Add(new Identifier()
        //        {
        //            Type = "PropertyValue",
        //            Name = "OID",
        //            Value = "2.16.764.1.4.1.1.8.1.1"
        //        });
        //        context.SchemaVersion = "1.0";
        //        context.Author = new Author();
        //        context.Author.Type = "Organization";
        //        context.Author.Name = "ETDA";
        //        payload.vc.credentialSubject.documentContext = context;

        //        TedaDocumentInformation docInform = new TedaDocumentInformation();
        //        docInform.Type = "DigitalDocument";
        //        docInform.Identifier = new IdentifierDocument();
        //        docInform.Identifier.Type = "PropertyValue";
        //        docInform.Identifier.PropertyID = "PID ID";
        //        docInform.Identifier.Value = "123456";
        //        docInform.Name = "PID Name";
        //        docInform.AdditionalType = "รหัสระบุประเภทเอกสาร";
        //        docInform.EducationalUse = "วัตถุประสงค์";
        //        docInform.DatePublished = "Issue Date";
        //        docInform.Description = "Description of the document";

        //        docInform.InLanguage = new Language();
        //        docInform.InLanguage.Name = "Thai";
        //        docInform.InLanguage.Type = "Language";
        //        docInform.InLanguage.AlternateName = "th";
        //        payload.vc.credentialSubject.tedadocumentInformation = docInform;


        //        TedaStudent item = new TedaStudent();
        //        item.Type = "Person";
        //        item.Identifier = new Identifier();
        //        item.Identifier.Type = "PropertyValue";
        //        item.Identifier.Name = "StudenID";
        //        item.Identifier.Value = "123456";

        //        item.HonorificPrefix = "นาย";
        //        item.GivenName = "ทดสอบ";
        //        item.FamilyName = "เอกสารดิจิตัล";
        //        item.Gender = "1";
        //        item.BirthDate = "2015-01-30";
        //        item.Nationality = "TH";

        //        ResidentCountryOrTerritory res = new ResidentCountryOrTerritory();
        //        res.Type = "PostalAddress";
        //        res.addressCountry = "TH";
        //        item.ResidentCountryOrTerritory = res;
        //        item.Image = "/examples/jvanzweden_s.jpg";
        //        item.FacultyName = "คณะวิศวกรรมศาสตร์";

        //        ProgramContext program = new ProgramContext();
        //        program.Type = "EducationalOccupationalProgram";
        //        program.Identifier = new Identifier();
        //        program.Identifier.Type = "PropertyValue";
        //        program.Identifier.Name = "ProgramID";
        //        program.Identifier.Value = "123456";
        //        program.Name = "ชื่อหลักสูตร";
        //        program.ProgramType.Add(new ProgramType()
        //        {
        //            Type = "DefinedTerm",
        //            Name = "กลุ่มสาขาหลัก",
        //            TermCode = "Major"

        //        });
        //        program.EndDate = "2023-01-01";
        //        program.NumberOfCredits = 8;
        //        program.EducationalCredentialAwarded = "เกียรตินิยมอันดับ 1";

        //        program.ProgramPrerequisites = new ProgramPrerequisites();
        //        program.ProgramPrerequisites.Type = "EducationalOccupationalCredential";
        //        program.ProgramPrerequisites.EducationalLevel = "ป.ตรี";
        //        program.ProgramPrerequisites.RecognizedBy = "สถาบันการศึกษาก่อนหน้า";

        //        item.ProgramContext = program;
        //        payload.vc.credentialSubject.tedastudent = item;


        //        AcademicSummaryDetails academicSummary = new AcademicSummaryDetails();
        //        academicSummary.Type = "teda:AcademicSummary";

        //        SemesterSummary summary = new SemesterSummary();
        //        summary.Type = "teda:semester";
        //        summary.EducationTypeSystem = "ทวิภาค";
        //        summary.SemesterStatus = "ปกติ";
        //        summary.SemesterName = "ภาคการศึกษา1";
        //        summary.Year = "2023";
        //        summary.SemesterCreditValue = 60;
        //        summary.SemesterCreditEarned = 45;
        //        summary.SemesterCreditCalculated = 46;
        //        summary.SemesterPointEarned = 120;
        //        summary.SemesterGPA = 3.8;
        //        summary.SemesterGPAX = 3.8;
        //        summary.Remark = "";
        //        payload.vc.credentialSubject.academicSummary = academicSummary;
        //        payload.vc.credentialSubject.academicSummary.SemesterSummaries.Add(summary);


        //        OrganizationDetails orgEdu = new OrganizationDetails();
        //        orgEdu.Type = "EducationalOrganization";
        //        orgEdu.Identifier = new Identifier();
        //        orgEdu.Identifier.Type = "PropertyValue";
        //        orgEdu.Identifier.Name = "OrganizationID";
        //        orgEdu.Identifier.Value = "123456";
        //        orgEdu.Name = "University Name";
        //        orgEdu.SchoolLevel = "ปริญญาตรี";
        //        orgEdu.Address = new PostalAddress();
        //        orgEdu.Address.Type = "PostalAddress";
        //        orgEdu.Address.StreetAddress = "Street Address";
        //        orgEdu.Address.AddressLocality = "City";
        //        orgEdu.Address.AddressRegion = "State/Region";
        //        orgEdu.Address.PostalCode = "Postal Code";
        //        orgEdu.Address.AddressCountry = "Country";

        //        orgEdu.SubOrganization = new SubOrganization();
        //        orgEdu.SubOrganization.Identifier = new Identifier();
        //        orgEdu.SubOrganization.Identifier.Type = "PropertyValue";
        //        orgEdu.SubOrganization.Identifier.Name = "CampusID";
        //        orgEdu.SubOrganization.Identifier.Value = "123456";
        //        orgEdu.SubOrganization.Name = "Campu Name";
        //        orgEdu.SubOrganization.Address = new PostalAddress();
        //        orgEdu.SubOrganization.Address.Type = "PostalAddress";
        //        orgEdu.SubOrganization.Address.StreetAddress = "Street Address";
        //        orgEdu.SubOrganization.Address.AddressLocality = "City";
        //        orgEdu.SubOrganization.Address.AddressRegion = "State/Region";
        //        orgEdu.SubOrganization.Address.PostalCode = "Postal Code";
        //        orgEdu.SubOrganization.Address.AddressCountry = "Country";

        //        orgEdu.Registrar = new Registrar();
        //        orgEdu.Registrar.Type = "Person";
        //        orgEdu.Registrar.Identifier = new Identifier();
        //        orgEdu.Registrar.Identifier.Type = "PropertyValue";
        //        orgEdu.Registrar.Identifier.Name = "Registrar ID";
        //        orgEdu.Registrar.Identifier.Value = "123456";

        //        orgEdu.Registrar.JobTitle = "นายทะเบียน";
        //        orgEdu.Registrar.HonorificPrefix = "นางสาว";
        //        orgEdu.Registrar.HonorificPrefix = "นางสาว";
        //        orgEdu.Registrar.Name = "ชื่อ-นามสกุลนายทะเบียน";
        //        orgEdu.Registrar.Email = "email";

        //        CourseList courseList = new CourseList();
        //        Course course = new Course();
        //        course.Type = "Course";
        //        course.CourseCode = "Course Code";
        //        course.Name = "Computer Science 101";
        //        course.AdditionalType = "หมวดวิชาเทคโนโลยีสารสนเทศ";
        //        course.Description = "Course Description";
        //        course.NumberOfCredits = 1;
        //        course.CreditEarned = 3;
        //        course.Grade = 4;
        //        course.GradeText = "A";
        //        course.PointEarned = 12;
        //        courseList.ItemList.Add(course);


        //        CredentialStatus credentialStatus = new CredentialStatus();
        //        credentialStatus.Id = "https://example.com/credentials/status/3#94567";
        //        credentialStatus.Type = "BitstringStatusListEntry";
        //        credentialStatus.StatusPurpose = "revocation";
        //        credentialStatus.StatusListIndex = "94567";
        //        credentialStatus.StatusListCredential = "https://example.com/credentials/status/3";
        //        payload.vc.credentialStatus = credentialStatus;

        //        CredentialSchema credentialSchema = new CredentialSchema();
        //        credentialSchema.id = "https://schemas-uat.teda.th/teda/teda-objects/common/verified-credential/transcript/-/blob/main/schema/transcript_vc_schema.json";
        //        credentialSchema.type = "JsonSchema";
        //        payload.vc.credentialSchema = credentialSchema;

        //        payload.vc.credentialSubject.educationalOrganization = orgEdu;

        //        var writeToken = JsonSerializer.Serialize(model, options);
        //        //**Database.Write(client, "VC", writeToken);


        //    }
        //    catch (Exception e)
        //    {
        //        //
        //        token = new JsonResult(new { error = e.Message })
        //        {
        //            StatusCode = 400
        //        };
        //    }

        //    return token;




        //}

    }


}
