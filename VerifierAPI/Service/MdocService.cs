using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.WebUtilities;
using Newtonsoft.Json;

namespace VerifierAPI.Service
{
    // FIX (H-01 follow-up / NFC-mdoc support, 2026-08-11): support for verifying
    // ISO/IEC 18013-5 mdoc presentations (OpenID4VP Credential Format
    // `mso_mdoc`, Appendix B.2), for a Wallet that talks to its own NFC reader
    // hardware directly (proximity, CBOR/COSE) but whose reader backend then
    // submits the resulting DeviceResponse to this Verifier over the normal
    // OpenID4VP request_uri/response_uri (redirect-invocation) flow — same
    // architecture as the existing JWT/SD-JWT paths in VerifierController, just
    // a different Credential Format and a different (CBOR/COSE, not JOSE)
    // encoding.
    //
    // Trust model, per explicit decision for this deployment: IssuerAuth is
    // resolved via this codebase's existing did:key infrastructure
    // (VCService.ResolveDID, using the COSE protected header's `kid` — same
    // idea as the JOSE `kid` used by the JWT/SD-JWT paths), NOT the X.509
    // `x5chain` cert-chain trust model ISO/IEC 18013-5 normally uses. This
    // avoids standing up a separate CA trust store for this test/bootcamp
    // environment. IssuerAuth and DeviceAuth are both ES256 (COSE alg -7,
    // P-256) only — DeviceMac (HMAC-based DeviceAuth) is not supported.
    //
    // UNVERIFIED: this was written without any build/test capability (the
    // sandbox used for this engagement has been unavailable this entire
    // session) and without real DeviceResponse bytes from the NFC device/
    // Wallet described by the user to test against. CBOR/COSE encoding is
    // exacting — this needs real interop testing against the actual hardware
    // before being trusted, more so than any other change in this engagement.
    // See OID4VP-1.0-COMPLIANCE-AUDIT.md finding H-01.
    public class MdocVerificationResult
    {
        public bool IsValid { get; set; }
        public string ErrorCode { get; set; }
        public string ErrorMessage { get; set; }
        public string DocType { get; set; }
        public Dictionary<string, object> VerifiedClaims { get; set; } = new Dictionary<string, object>();
    }

    public class MdocService
    {
        // ---- Minimal CBOR object-graph model ----
        // System.Formats.Cbor's CborReader is a low-level pull parser; these
        // small node types let the rest of this file walk mdoc structures the
        // same way the rest of the codebase walks JsonElement trees. Maps are
        // kept as an ordered list of (key, value) pairs (not a Dictionary) so
        // CborNode doesn't need custom Equals/GetHashCode — mdoc maps here are
        // small, so linear lookup is fine.
        private abstract class CborNode { }
        private sealed class CborMapNode : CborNode { public List<(CborNode Key, CborNode Value)> Entries = new(); }
        private sealed class CborArrayNode : CborNode { public List<CborNode> Items = new(); }
        private sealed class CborTextNode : CborNode { public string Value = ""; }
        private sealed class CborBytesNode : CborNode { public byte[] Value = Array.Empty<byte>(); }
        private sealed class CborIntNode : CborNode { public long Value; }
        private sealed class CborBoolNode : CborNode { public bool Value; }
        private sealed class CborNullNode : CborNode { }

        // Tag 24 (EncodedCborDataItem) is the one tag mdoc relies on pervasively
        // (every "...Bytes" field — IssuerSignedItemBytes, MobileSecurityObjectBytes,
        // DeviceNameSpacesBytes, DeviceAuthenticationBytes — is "a bstr containing
        // the CBOR encoding of X, tagged 24"). We keep the RAW content bytes of
        // the inner bstr here instead of recursively decoding, because callers
        // need those exact bytes for digest/signature computation, not just the
        // decoded structure — decoding (if needed) happens separately from
        // RawContentBytes via a fresh CborReader.
        private sealed class CborTaggedNode : CborNode { public CborTag Tag; public byte[] RawContentBytes = Array.Empty<byte>(); }

        private static CborNode Decode(CborReader reader)
        {
            switch (reader.PeekState())
            {
                case CborReaderState.StartMap:
                    {
                        var node = new CborMapNode();
                        reader.ReadStartMap();
                        while (reader.PeekState() != CborReaderState.EndMap)
                        {
                            var key = Decode(reader);
                            var val = Decode(reader);
                            node.Entries.Add((key, val));
                        }
                        reader.ReadEndMap();
                        return node;
                    }
                case CborReaderState.StartArray:
                    {
                        var node = new CborArrayNode();
                        reader.ReadStartArray();
                        while (reader.PeekState() != CborReaderState.EndArray)
                        {
                            node.Items.Add(Decode(reader));
                        }
                        reader.ReadEndArray();
                        return node;
                    }
                case CborReaderState.TextString:
                case CborReaderState.StartIndefiniteLengthTextString:
                    return new CborTextNode { Value = reader.ReadTextString() };
                case CborReaderState.ByteString:
                case CborReaderState.StartIndefiniteLengthByteString:
                    return new CborBytesNode { Value = reader.ReadByteString() };
                case CborReaderState.UnsignedInteger:
                case CborReaderState.NegativeInteger:
                    return new CborIntNode { Value = reader.ReadInt64() };
                case CborReaderState.Boolean:
                    return new CborBoolNode { Value = reader.ReadBoolean() };
                case CborReaderState.Null:
                    reader.ReadNull();
                    return new CborNullNode();
                case CborReaderState.Tag:
                    {
                        CborTag tag = reader.ReadTag();
                        if (tag == CborTag.EncodedCborDataItem &&
                            (reader.PeekState() == CborReaderState.ByteString || reader.PeekState() == CborReaderState.StartIndefiniteLengthByteString))
                        {
                            return new CborTaggedNode { Tag = tag, RawContentBytes = reader.ReadByteString() };
                        }
                        // Other tags (e.g. tag 0 `tdate`) — decode the tagged value
                        // itself and return it directly; date strings end up as a
                        // plain CborTextNode, which ParseCborDate reads.
                        return Decode(reader);
                    }
                default:
                    // Floats / other simple values we don't expect anywhere we
                    // actually look — skip rather than get stuck.
                    reader.SkipValue();
                    return new CborNullNode();
            }
        }

        private static CborNode? MapGet(CborMapNode? map, string key)
        {
            if (map == null) return null;
            foreach (var (k, v) in map.Entries)
                if (k is CborTextNode t && t.Value == key) return v;
            return null;
        }

        private static CborNode? MapGet(CborMapNode? map, long key)
        {
            if (map == null) return null;
            foreach (var (k, v) in map.Entries)
                if (k is CborIntNode i && i.Value == key) return v;
            return null;
        }

        private static DateTimeOffset? ParseCborDate(CborNode? node)
        {
            if (node is CborTextNode t &&
                DateTimeOffset.TryParse(t.Value, System.Globalization.CultureInfo.InvariantCulture,
                    System.Globalization.DateTimeStyles.RoundtripKind, out var dto))
            {
                return dto;
            }
            return null;
        }

        private static object? CborNodeToPlainValue(CborNode? node)
        {
            switch (node)
            {
                case CborTextNode t: return t.Value;
                case CborIntNode i: return i.Value;
                case CborBoolNode b: return b.Value;
                case CborBytesNode by: return Convert.ToBase64String(by.Value);
                case CborNullNode: return null;
                case CborArrayNode arr: return arr.Items.Select(CborNodeToPlainValue).ToList();
                case CborMapNode m: return m.Entries.ToDictionary(
                    e => CborNodeToPlainValue(e.Key)?.ToString() ?? "",
                    e => CborNodeToPlainValue(e.Value));
                case CborTaggedNode tg: return Convert.ToBase64String(tg.RawContentBytes);
                default: return null;
            }
        }

        // Re-encodes `content` as a full `#6.24(bstr .cbor X)` — i.e. the tag-24
        // marker plus the byte-string header plus the bytes themselves — since
        // that FULL encoding, not just the inner bytes, is what mdoc digests and
        // detached-signature payloads are computed over (ISO 18013-5 §9.1.2.5).
        private static byte[] WrapAsTag24(byte[] content)
        {
            var writer = new CborWriter(CborConformanceMode.Lax);
            writer.WriteTag(CborTag.EncodedCborDataItem);
            writer.WriteByteString(content);
            return writer.Encode();
        }

        private static byte[] ComputeDigest(byte[] data, string? algName)
        {
            return (algName ?? "SHA-256").ToUpperInvariant() switch
            {
                "SHA-256" or "SHA256" => SHA256.HashData(data),
                "SHA-384" or "SHA384" => SHA384.HashData(data),
                "SHA-512" or "SHA512" => SHA512.HashData(data),
                _ => throw new NotSupportedException($"Unsupported digestAlgorithm: {algName}")
            };
        }

        // COSE Sig_structure ("Signature1"), RFC 8152 §4.4 — used for both
        // IssuerAuth and DeviceAuth (DeviceSignature) verification.
        private static byte[] BuildCoseSigStructure(byte[] protectedHeaderBytes, byte[] payloadBytes)
        {
            var writer = new CborWriter(CborConformanceMode.Lax);
            writer.WriteStartArray(4);
            writer.WriteTextString("Signature1");
            writer.WriteByteString(protectedHeaderBytes);
            writer.WriteByteString(Array.Empty<byte>()); // external_aad — always empty here
            writer.WriteByteString(payloadBytes);
            writer.WriteEndArray();
            return writer.Encode();
        }

        // COSE ECDSA signatures (alg -7 / ES256) use the same raw r||s (IEEE
        // P1363) concatenation as JOSE ES256 (RFC 8152 §8.1) — reuses the exact
        // verification approach VCService.VerifyJWS already uses for ES256 JWS.
        private static bool VerifyCoseEs256(byte[] sigStructureBytes, byte[] signature, string publicKeyEs256Json, out string errMsg)
        {
            errMsg = "";
            try
            {
                var keyMaterial = JsonConvert.DeserializeObject<Dictionary<string, string>>(publicKeyEs256Json);
                if (keyMaterial == null || !keyMaterial.TryGetValue("x", out var xB64) || !keyMaterial.TryGetValue("y", out var yB64))
                {
                    errMsg = "Resolved key is not a P-256 {x,y} key — only ES256 IssuerAuth/DeviceAuth is supported";
                    return false;
                }
                var ecParams = new ECParameters
                {
                    Curve = ECCurve.NamedCurves.nistP256,
                    Q = new ECPoint
                    {
                        X = WebEncoders.Base64UrlDecode(xB64),
                        Y = WebEncoders.Base64UrlDecode(yB64)
                    }
                };
                using var ecdsa = ECDsa.Create(ecParams);
                bool isValid = ecdsa.VerifyData(sigStructureBytes, signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
                if (!isValid) errMsg = "signature is invalid";
                return isValid;
            }
            catch (Exception e)
            {
                errMsg = e.Message;
                return false;
            }
        }

        // Decodes a COSE_Key (RFC 9053 §7) restricted to EC2/P-256 (kty=2,
        // crv=1) — the only device-key shape this deployment supports (ES256
        // DeviceAuth) — into the same {"crv","x","y"} JSON blob VerifyCoseEs256
        // (and VCService.VerifyJWS's ES256 path) expect.
        private static string? DecodeCoseKeyAsEs256Blob(CborMapNode coseKey, out string errMsg)
        {
            errMsg = "";
            if (MapGet(coseKey, 1L) is not CborIntNode ktyNode || ktyNode.Value != 2)
            {
                errMsg = "deviceKey is not an EC2 COSE_Key — only P-256 device keys are supported";
                return null;
            }
            if (MapGet(coseKey, -1L) is not CborIntNode crvNode || crvNode.Value != 1)
            {
                errMsg = "deviceKey curve is not P-256";
                return null;
            }
            byte[]? x = (MapGet(coseKey, -2L) as CborBytesNode)?.Value;
            byte[]? y = (MapGet(coseKey, -3L) as CborBytesNode)?.Value;
            if (x == null || y == null)
            {
                errMsg = "deviceKey is missing x/y coordinates";
                return null;
            }
            return JsonConvert.SerializeObject(new { crv = "P-256", x = WebEncoders.Base64UrlEncode(x), y = WebEncoders.Base64UrlEncode(y) });
        }

        // SessionTranscript = [DeviceEngagementBytes(null), EReaderKeyBytes(null),
        // OpenID4VPHandover] for the redirect-invocation case (Verifier reached
        // over request_uri/response_uri, no separate proximity engagement — e.g.
        // a purely remote mdoc presentation with no NFC/BLE involved), where
        // OpenID4VPHandover = ["OpenID4VPHandover", sha256(CBOR(OpenID4VPHandoverInfo))]
        // and OpenID4VPHandoverInfo = [client_id, nonce, jwkThumbprint, response_uri].
        // jwkThumbprint MUST be null here since this Verifier's response_mode is
        // `direct_post` (unencrypted), not `direct_post.jwt`.
        // See OpenID4VP Appendix B.2.6.1.
        //
        // NOT used by this deployment's actual NFC flow — kept only as a
        // fallback for a hypothetical purely-remote mdoc session with no real
        // proximity engagement. See BuildProximitySessionTranscript below for
        // the variant this deployment's real NFC reader/wallet needs.
        private static byte[] BuildRedirectSessionTranscript(string clientId, string nonce, string responseUri)
        {
            var infoWriter = new CborWriter(CborConformanceMode.Lax);
            infoWriter.WriteStartArray(4);
            infoWriter.WriteTextString(clientId);
            infoWriter.WriteTextString(nonce);
            infoWriter.WriteNull();
            infoWriter.WriteTextString(responseUri);
            infoWriter.WriteEndArray();
            byte[] handoverInfoBytes = infoWriter.Encode();
            byte[] handoverInfoHash = SHA256.HashData(handoverInfoBytes);

            var handoverWriter = new CborWriter(CborConformanceMode.Lax);
            handoverWriter.WriteStartArray(2);
            handoverWriter.WriteTextString("OpenID4VPHandover");
            handoverWriter.WriteByteString(handoverInfoHash);
            handoverWriter.WriteEndArray();
            byte[] handoverBytes = handoverWriter.Encode();

            var transcriptWriter = new CborWriter(CborConformanceMode.Lax);
            transcriptWriter.WriteStartArray(3);
            transcriptWriter.WriteNull();
            transcriptWriter.WriteNull();
            transcriptWriter.WriteEncodedValue(handoverBytes);
            transcriptWriter.WriteEndArray();
            return transcriptWriter.Encode();
        }

        // SessionTranscript = [DeviceEngagementBytes, EReaderKeyBytes, Handover]
        // per ISO/IEC 18013-5 §9.1.5.1 — used as-is (NOT the OpenID4VP
        // Appendix B.2.6 override) for this deployment's real NFC proximity
        // engagement, per explicit confirmation that the reader/wallet perform a
        // genuine DeviceEngagement/EReaderKey handshake over NFC rather than a
        // purely remote OpenID4VP exchange.
        //
        // deviceEngagementBytes / eReaderKeyBytes are the RAW (not yet tag-24
        // wrapped) CBOR encodings of the DeviceEngagement and EReaderKey
        // structures captured by the reader app during the NFC tap — this
        // method wraps them in `#6.24(bstr ...)` itself (DeviceEngagementBytes /
        // EReaderKeyBytes are both "...Bytes"-suffixed types, so tag-24-wrapped,
        // per the same convention as every other "...Bytes" field elsewhere in
        // this file).
        //
        // handoverSelectMessage / handoverRequestMessage are the raw NFC Forum
        // Handover Select / Handover Request message bytes from the NFC
        // exchange itself (used as plain byte strings, NOT tag-24 wrapped —
        // Handover Select/Request Message are typed as plain `bstr` in the
        // ISO 18013-5 CDDL, unlike the "...Bytes" fields above).
        // handoverRequestMessage is null for static handover (no separate
        // Handover Request Message was exchanged).
        //
        // CAVEAT: this was written from secondary/reference-implementation
        // knowledge of the ISO/IEC 18013-5 CDDL, not the normative standard
        // text itself (ISO 18013-5 is a paywalled ISO standard, not available
        // to fetch/verify in this environment). This is the highest-risk piece
        // in this whole change — please cross-check the exact byte layout
        // against your reader app/wallet's own implementation of the standard
        // before trusting DeviceAuth verification results.
        private static byte[] BuildProximitySessionTranscript(
            byte[] deviceEngagementBytes,
            byte[] eReaderKeyBytes,
            byte[] handoverSelectMessage,
            byte[]? handoverRequestMessage)
        {
            byte[] deviceEngagementBytesTagged = WrapAsTag24(deviceEngagementBytes);
            byte[] eReaderKeyBytesTagged = WrapAsTag24(eReaderKeyBytes);

            var handoverWriter = new CborWriter(CborConformanceMode.Lax);
            handoverWriter.WriteStartArray(2);
            handoverWriter.WriteByteString(handoverSelectMessage);
            if (handoverRequestMessage != null)
            {
                handoverWriter.WriteByteString(handoverRequestMessage);
            }
            else
            {
                handoverWriter.WriteNull();
            }
            handoverWriter.WriteEndArray();
            byte[] handoverBytes = handoverWriter.Encode();

            var transcriptWriter = new CborWriter(CborConformanceMode.Lax);
            transcriptWriter.WriteStartArray(3);
            transcriptWriter.WriteEncodedValue(deviceEngagementBytesTagged);
            transcriptWriter.WriteEncodedValue(eReaderKeyBytesTagged);
            transcriptWriter.WriteEncodedValue(handoverBytes);
            transcriptWriter.WriteEndArray();
            return transcriptWriter.Encode();
        }

        // Verifies an mso_mdoc presentation (base64url-encoded ISO 18013-5
        // DeviceResponse, per OpenID4VP Appendix B.2.5) — IssuerAuth signature,
        // MSO validity period, every disclosed element's digest, and DeviceAuth
        // (proof of possession of the mdoc's device key, bound to this exact
        // session via SessionTranscript). Mirrors the shape of
        // VCService.VerifySDJWTPresentation (SdJwtVerificationResult) so
        // VerifierController can handle both similarly.
        //
        // deviceEngagementBytes/eReaderKeyBytes/handoverSelectMessage are
        // REQUIRED for this deployment's real NFC proximity flow (see
        // BuildProximitySessionTranscript) — the reader app must forward the
        // raw CBOR/NFC-handover bytes it captured during the NFC tap alongside
        // the DeviceResponse, since standard OpenID4VP's vp_token has no slot
        // for them. If left null (e.g. a hypothetical purely-remote mdoc
        // session with no NFC/BLE engagement at all), this falls back to the
        // OpenID4VP Appendix B.2.6.1 redirect-invocation SessionTranscript
        // instead — expectedClientId/expectedNonce/expectedResponseUri are only
        // used in that fallback case.
        public MdocVerificationResult VerifyMdocPresentation(
            string base64UrlDeviceResponse,
            string expectedClientId,
            string expectedNonce,
            string expectedResponseUri,
            VCService vcServ,
            byte[]? deviceEngagementBytes = null,
            byte[]? eReaderKeyBytes = null,
            byte[]? handoverSelectMessage = null,
            byte[]? handoverRequestMessage = null)
        {
            var result = new MdocVerificationResult();
            try
            {
                byte[] deviceResponseBytes;
                try
                {
                    deviceResponseBytes = vcServ.Base64UrlDecode(base64UrlDeviceResponse);
                }
                catch
                {
                    result.ErrorCode = "malformed_mdoc";
                    result.ErrorMessage = "vp_token is not valid base64url";
                    return result;
                }

                CborNode top;
                try
                {
                    var reader = new CborReader(deviceResponseBytes, CborConformanceMode.Lax);
                    top = Decode(reader);
                }
                catch (Exception e)
                {
                    result.ErrorCode = "malformed_mdoc";
                    result.ErrorMessage = "DeviceResponse is not valid CBOR: " + e.Message;
                    return result;
                }

                if (top is not CborMapNode topMap)
                {
                    result.ErrorCode = "malformed_mdoc";
                    result.ErrorMessage = "DeviceResponse is not a CBOR map";
                    return result;
                }

                if (MapGet(topMap, "documents") is not CborArrayNode documents || documents.Items.Count == 0)
                {
                    result.ErrorCode = "missing_mdoc_document";
                    result.ErrorMessage = "DeviceResponse has no documents (Wallet may have returned documentErrors instead)";
                    return result;
                }

                // Only the first document is verified — this Verifier's DCQL
                // queries ask for exactly one credential per session, matching
                // the existing SD-JWT/jwt_vc_json paths.
                if (documents.Items[0] is not CborMapNode doc)
                {
                    result.ErrorCode = "malformed_mdoc";
                    result.ErrorMessage = "documents[0] is not a CBOR map";
                    return result;
                }

                string? docType = (MapGet(doc, "docType") as CborTextNode)?.Value;
                if (string.IsNullOrEmpty(docType))
                {
                    result.ErrorCode = "malformed_mdoc";
                    result.ErrorMessage = "Document is missing docType";
                    return result;
                }
                result.DocType = docType;

                if (MapGet(doc, "issuerSigned") is not CborMapNode issuerSigned)
                {
                    result.ErrorCode = "malformed_mdoc";
                    result.ErrorMessage = "Document is missing issuerSigned";
                    return result;
                }

                // ---- 1. IssuerAuth = COSE_Sign1 over MobileSecurityObjectBytes ----
                if (MapGet(issuerSigned, "issuerAuth") is not CborArrayNode issuerAuthArr || issuerAuthArr.Items.Count != 4)
                {
                    result.ErrorCode = "invalid_issuer_signature";
                    result.ErrorMessage = "issuerAuth is not a COSE_Sign1 structure";
                    return result;
                }
                byte[]? issuerProtectedHeaderBytes = (issuerAuthArr.Items[0] as CborBytesNode)?.Value;
                byte[]? issuerPayloadBytes = (issuerAuthArr.Items[2] as CborBytesNode)?.Value;
                byte[]? issuerSignatureBytes = (issuerAuthArr.Items[3] as CborBytesNode)?.Value;
                if (issuerProtectedHeaderBytes == null || issuerPayloadBytes == null || issuerSignatureBytes == null)
                {
                    result.ErrorCode = "invalid_issuer_signature";
                    result.ErrorMessage = "issuerAuth COSE_Sign1 fields are malformed";
                    return result;
                }

                // Resolve the issuer's public key via this deployment's existing
                // did:key infrastructure (VCService.ResolveDID), using the COSE
                // protected header's `kid` (label 4) the same way the JWT/SD-JWT
                // paths use the JOSE header's `kid`.
                string? issuerKid = null;
                try
                {
                    var headerNode = Decode(new CborReader(issuerProtectedHeaderBytes, CborConformanceMode.Lax));
                    if (headerNode is CborMapNode headerMap)
                    {
                        var kidNode = MapGet(headerMap, 4L);
                        if (kidNode is CborBytesNode kidBytes) issuerKid = Encoding.UTF8.GetString(kidBytes.Value);
                        else if (kidNode is CborTextNode kidText) issuerKid = kidText.Value;
                    }
                }
                catch
                {
                    // handled by the null-check below
                }

                if (string.IsNullOrEmpty(issuerKid))
                {
                    result.ErrorCode = "invalid_issuer_signature";
                    result.ErrorMessage = "issuerAuth protected header has no kid to resolve the issuer's did:key";
                    return result;
                }

                string issuerDid = issuerKid.Contains('#') ? issuerKid.Split('#')[0] : issuerKid;
                string? issuerPublicKey;
                try
                {
                    issuerPublicKey = vcServ.ResolveDID(issuerDid, issuerKid).Result;
                }
                catch (Exception e)
                {
                    result.ErrorCode = "invalid_issuer_signature";
                    result.ErrorMessage = "Failed to resolve issuer did:key: " + e.Message;
                    return result;
                }
                if (string.IsNullOrEmpty(issuerPublicKey))
                {
                    result.ErrorCode = "invalid_issuer_signature";
                    result.ErrorMessage = "Issuer did:key did not resolve to a usable public key";
                    return result;
                }

                byte[] issuerSigStructure = BuildCoseSigStructure(issuerProtectedHeaderBytes, issuerPayloadBytes);
                if (!VerifyCoseEs256(issuerSigStructure, issuerSignatureBytes, issuerPublicKey, out string issuerSigErr))
                {
                    result.ErrorCode = "invalid_issuer_signature";
                    result.ErrorMessage = issuerSigErr;
                    return result;
                }

                // ---- 2. Unwrap MobileSecurityObjectBytes from the IssuerAuth payload ----
                byte[] msoBytes;
                try
                {
                    var payloadNode = Decode(new CborReader(issuerPayloadBytes, CborConformanceMode.Lax));
                    if (payloadNode is not CborTaggedNode msoTagged || msoTagged.Tag != CborTag.EncodedCborDataItem)
                    {
                        result.ErrorCode = "malformed_mdoc";
                        result.ErrorMessage = "IssuerAuth payload is not MobileSecurityObjectBytes (tag 24)";
                        return result;
                    }
                    msoBytes = msoTagged.RawContentBytes;
                }
                catch (Exception e)
                {
                    result.ErrorCode = "malformed_mdoc";
                    result.ErrorMessage = "Failed to unwrap MobileSecurityObjectBytes: " + e.Message;
                    return result;
                }

                if (Decode(new CborReader(msoBytes, CborConformanceMode.Lax)) is not CborMapNode mso)
                {
                    result.ErrorCode = "malformed_mdoc";
                    result.ErrorMessage = "MobileSecurityObject is not a CBOR map";
                    return result;
                }

                string? msoDocType = (MapGet(mso, "docType") as CborTextNode)?.Value;
                if (!string.Equals(msoDocType, docType, StringComparison.Ordinal))
                {
                    result.ErrorCode = "doctype_mismatch";
                    result.ErrorMessage = "MSO docType does not match the Document's docType";
                    return result;
                }

                string digestAlgName = (MapGet(mso, "digestAlgorithm") as CborTextNode)?.Value ?? "SHA-256";

                // ---- 3. Validity period ----
                if (MapGet(mso, "validityInfo") is CborMapNode validityInfo)
                {
                    DateTimeOffset? validFrom = ParseCborDate(MapGet(validityInfo, "validFrom"));
                    DateTimeOffset? validUntil = ParseCborDate(MapGet(validityInfo, "validUntil"));
                    var now = DateTimeOffset.UtcNow;
                    const int skewSeconds = 60;
                    if (validFrom.HasValue && now < validFrom.Value.AddSeconds(-skewSeconds))
                    {
                        result.ErrorCode = "credential_not_yet_valid";
                        return result;
                    }
                    if (validUntil.HasValue && now > validUntil.Value.AddSeconds(skewSeconds))
                    {
                        result.ErrorCode = "credential_expired";
                        return result;
                    }
                }

                // ---- 4. Device key — mdoc's holder-binding key, equivalent to SD-JWT's cnf.jwk ----
                var deviceKeyInfo = MapGet(mso, "deviceKeyInfo") as CborMapNode;
                var deviceKeyNode = deviceKeyInfo != null ? MapGet(deviceKeyInfo, "deviceKey") as CborMapNode : null;
                if (deviceKeyNode == null)
                {
                    result.ErrorCode = "missing_holder_binding_key";
                    result.ErrorMessage = "MSO has no deviceKeyInfo.deviceKey";
                    return result;
                }
                string? devicePublicKey = DecodeCoseKeyAsEs256Blob(deviceKeyNode, out string deviceKeyErr);
                if (devicePublicKey == null)
                {
                    result.ErrorCode = "missing_holder_binding_key";
                    result.ErrorMessage = deviceKeyErr;
                    return result;
                }

                // ---- 5. Selective disclosure — verify every disclosed element's digest ----
                var valueDigestsNode = MapGet(mso, "valueDigests") as CborMapNode;
                var verifiedClaims = new Dictionary<string, object>();
                if (MapGet(issuerSigned, "nameSpaces") is CborMapNode nameSpacesMap)
                {
                    foreach (var (nsKeyNode, nsItemsNode) in nameSpacesMap.Entries)
                    {
                        string? ns = (nsKeyNode as CborTextNode)?.Value;
                        if (ns == null || nsItemsNode is not CborArrayNode itemsArr) continue;

                        var digestsForNs = valueDigestsNode != null ? MapGet(valueDigestsNode, ns) as CborMapNode : null;

                        foreach (var itemNode in itemsArr.Items)
                        {
                            if (itemNode is not CborTaggedNode taggedItem || taggedItem.Tag != CborTag.EncodedCborDataItem)
                            {
                                result.ErrorCode = "malformed_mdoc";
                                result.ErrorMessage = $"nameSpaces['{ns}'] entry is not an IssuerSignedItemBytes (tag 24)";
                                return result;
                            }

                            // Digest is computed over the FULL tag+bstr+content
                            // encoding of this IssuerSignedItemBytes, per ISO
                            // 18013-5 §9.1.2.5 — not just the inner
                            // IssuerSignedItem bytes.
                            byte[] fullItemBytes = WrapAsTag24(taggedItem.RawContentBytes);
                            byte[] computedDigest = ComputeDigest(fullItemBytes, digestAlgName);

                            if (Decode(new CborReader(taggedItem.RawContentBytes, CborConformanceMode.Lax)) is not CborMapNode itemFields)
                            {
                                result.ErrorCode = "malformed_mdoc";
                                result.ErrorMessage = $"nameSpaces['{ns}'] entry is not an IssuerSignedItem map";
                                return result;
                            }
                            long? digestId = (MapGet(itemFields, "digestID") as CborIntNode)?.Value;
                            string? elementIdentifier = (MapGet(itemFields, "elementIdentifier") as CborTextNode)?.Value;
                            CborNode? elementValueNode = MapGet(itemFields, "elementValue");

                            byte[]? expectedDigest = digestId.HasValue && digestsForNs != null
                                ? (MapGet(digestsForNs, digestId.Value) as CborBytesNode)?.Value
                                : null;

                            if (expectedDigest == null || !CryptographicOperations.FixedTimeEquals(computedDigest, expectedDigest))
                            {
                                result.ErrorCode = "disclosure_digest_mismatch";
                                result.ErrorMessage = $"Digest mismatch for {ns}.{elementIdentifier}";
                                return result;
                            }

                            if (!string.IsNullOrEmpty(elementIdentifier))
                            {
                                verifiedClaims[$"{ns}.{elementIdentifier}"] = CborNodeToPlainValue(elementValueNode)!;
                            }
                        }
                    }
                }

                // ---- 6. DeviceAuth — proof of possession of deviceKey, bound to this session ----
                if (MapGet(doc, "deviceSigned") is not CborMapNode deviceSigned)
                {
                    result.ErrorCode = "missing_kb_jwt"; // reuse the SD-JWT KB-JWT-required error family — same concept (holder proof-of-possession missing)
                    result.ErrorMessage = "Document is missing deviceSigned";
                    return result;
                }
                if (MapGet(deviceSigned, "nameSpaces") is not CborTaggedNode deviceNsTagged || deviceNsTagged.Tag != CborTag.EncodedCborDataItem)
                {
                    result.ErrorCode = "malformed_mdoc";
                    result.ErrorMessage = "deviceSigned.nameSpaces is not DeviceNameSpacesBytes (tag 24)";
                    return result;
                }
                byte[] deviceNameSpacesBytesFull = WrapAsTag24(deviceNsTagged.RawContentBytes);

                if (MapGet(deviceSigned, "deviceAuth") is not CborMapNode deviceAuth)
                {
                    result.ErrorCode = "missing_kb_jwt";
                    result.ErrorMessage = "Document is missing deviceSigned.deviceAuth";
                    return result;
                }
                if (MapGet(deviceAuth, "deviceSignature") is not CborArrayNode deviceSigArr || deviceSigArr.Items.Count != 4)
                {
                    result.ErrorCode = "invalid_kb_jwt_signature";
                    result.ErrorMessage = "deviceAuth.deviceSignature is missing or not a COSE_Sign1 (deviceMac/HMAC DeviceAuth is not supported by this deployment)";
                    return result;
                }
                byte[]? deviceProtectedHeaderBytes = (deviceSigArr.Items[0] as CborBytesNode)?.Value;
                byte[]? deviceSignatureBytes = (deviceSigArr.Items[3] as CborBytesNode)?.Value;
                if (deviceProtectedHeaderBytes == null || deviceSignatureBytes == null)
                {
                    result.ErrorCode = "invalid_kb_jwt_signature";
                    result.ErrorMessage = "deviceAuth.deviceSignature COSE_Sign1 fields are malformed";
                    return result;
                }

                // This deployment's real flow always supplies deviceEngagementBytes/
                // eReaderKeyBytes/handoverSelectMessage (see this method's leading
                // comment) — the redirect-invocation fallback below only exists for
                // a hypothetical mdoc session with no NFC/BLE engagement at all,
                // and is not expected to ever be hit in production here.
                bool hasProximityEngagement = deviceEngagementBytes != null && eReaderKeyBytes != null && handoverSelectMessage != null;
                byte[] sessionTranscriptBytes = hasProximityEngagement
                    ? BuildProximitySessionTranscript(deviceEngagementBytes!, eReaderKeyBytes!, handoverSelectMessage!, handoverRequestMessage)
                    : BuildRedirectSessionTranscript(expectedClientId, expectedNonce, expectedResponseUri);

                // DeviceAuthentication = ["DeviceAuthentication", SessionTranscript, DocType, DeviceNameSpacesBytes]
                var deviceAuthWriter = new CborWriter(CborConformanceMode.Lax);
                deviceAuthWriter.WriteStartArray(4);
                deviceAuthWriter.WriteTextString("DeviceAuthentication");
                deviceAuthWriter.WriteEncodedValue(sessionTranscriptBytes);
                deviceAuthWriter.WriteTextString(docType);
                deviceAuthWriter.WriteEncodedValue(deviceNameSpacesBytesFull);
                deviceAuthWriter.WriteEndArray();
                byte[] deviceAuthenticationBytes = WrapAsTag24(deviceAuthWriter.Encode());

                byte[] deviceSigStructure = BuildCoseSigStructure(deviceProtectedHeaderBytes, deviceAuthenticationBytes);
                if (!VerifyCoseEs256(deviceSigStructure, deviceSignatureBytes, devicePublicKey, out string deviceSigErr))
                {
                    result.ErrorCode = "invalid_kb_jwt_signature";
                    result.ErrorMessage = deviceSigErr;
                    return result;
                }

                result.IsValid = true;
                result.VerifiedClaims = verifiedClaims;
                return result;
            }
            catch (Exception e)
            {
                result.ErrorCode = "sd_jwt_verification_error"; // reuse the same generic error-code family as VerifySDJWTPresentation's catch-all
                result.ErrorMessage = e.Message;
                return result;
            }
        }
    }
}
