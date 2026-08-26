# OpenID4VP 1.0 Compliance and Security Audit

**Project:** `verifier-sdk`  
**Audited commit:** `07f020f351d0fe214dee05bf85c8eb42cf293b1e`  
**Audit date:** 2026-08-06  
**Normative reference:** [OpenID for Verifiable Presentations 1.0 Final](https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html), published July 2025

## Executive summary

The current implementation is **not compliant with OpenID4VP 1.0 Final and should not be used to make security decisions in production**.

The implementation appears to use a pre-final, project-specific response shape. A conforming OpenID4VP 1.0 Wallet response cannot be parsed correctly. More importantly, a signed presentation is not bound to the stored authorization request: the Verifier does not validate the stored `state`, `nonce`, `client_id`/audience, session expiry, requested credential, or one-time use. The SD-JWT path verifies only part of the object and does not verify holder binding or disclosure integrity.

The shortest safe remediation is to support one format correctly first—preferably `jwt_vc_json`—and reject every other format until its complete format-specific verifier exists. Do not claim SD-JWT VC or mdoc support based only on parsing or issuer-signature verification.

### Severity summary

| Severity | Count | Meaning |
|---|---:|---|
| Critical | 5 | Can cause acceptance of replayed, unbound, or incompletely verified credentials, or disclose production secrets/data |
| High | 10 | Breaks OpenID4VP 1.0 interoperability or important protocol/security requirements |
| Medium | 8 | Reliability, privacy, error-handling, and maintainability defects that obstruct a conformant implementation |

## Scope and method

The audit covered the TypeScript package, .NET API, authorization-request generation, Request URI endpoint, `direct_post` response endpoint, DCQL generation, JWS/DID/SD-JWT processing, session persistence, result endpoints, configuration, and existing tests.

This was a static source audit. Runtime conformance testing could not be completed because:

- The TypeScript package has no implementation or tests.
- The .NET project has no protocol test suite.
- The checked-in NuGet assets reference a Windows-only fallback directory, so a clean macOS build failed before compilation.

Passing the recommendations in this document is necessary but should not be treated as certification. The corrected implementation should also pass an independent interoperability/conformance test suite.

## Critical defects

### C-01 — The final OpenID4VP 1.0 `vp_token` structure is not supported

**Evidence**

- [`VerifierController.cs:438`](api/VerifierAPI/Controllers/VerifierController.cs#L438) binds `vp_token` as a string and immediately treats it as a presentation.
- [`VerifierController.cs:454`](api/VerifierAPI/Controllers/VerifierController.cs#L454) supports a bare JSON array as a compatibility special case.
- [`VerifierController.cs:474`](api/VerifierAPI/Controllers/VerifierController.cs#L474) passes the result directly to a compact-JWS parser.

OpenID4VP 1.0 requires `vp_token` to be a JSON-encoded object. Each key is a DCQL Credential Query `id`; each value is an array of one or more matching Presentations. See [§8.1 Response Parameters](https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html#section-8.1).

**Impact**

A conforming response such as the following cannot be processed:

```json
{
  "student_credential": ["eyJ..."]
}
```

The existing direct-JWS and bare-array behavior is incompatible with the final specification.

**Required fix**

Parse `vp_token` as a JSON object. For each entry:

1. Match the key to a Credential Query ID stored with the session.
2. Enforce the query's `multiple` rule.
3. Dispatch each Presentation to the verifier for the format requested by that query.
4. Reject unknown, duplicate, missing-required, malformed, or extra query results.

Remove the bare-array and direct-JWS compatibility paths unless they are isolated behind an explicitly named legacy protocol profile.

**Acceptance criteria**

- A valid final-format object succeeds.
- A bare JWS, bare array, unknown query ID, or invalid presentation count is rejected.
- Multiple returned queries are verified independently and then checked as a complete DCQL result.

### C-02 — Authorization responses are not bound to the stored transaction

**Evidence**

- [`VerifierController.cs:438`](api/VerifierAPI/Controllers/VerifierController.cs#L438) receives route `{id}` and form `state`, but never compares them.
- [`VerifierController.cs:501`](api/VerifierAPI/Controllers/VerifierController.cs#L501) reads a `jti` from a presentation but does not compare it with the route, form state, or database session.
- [`VerifierController.cs:608`](api/VerifierAPI/Controllers/VerifierController.cs#L608) stores the result using the untrusted form `state`.
- No response code reads and compares the session's stored `Nonce` or expected full `client_id`.

The specification requires every Verifiable Presentation to be bound to the exact `client_id` and `nonce` used in its Authorization Request. See [§14.1.2](https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html#section-14.1.2). A received `state` should also correspond to a recent Authorization Request; see [§14.3.2](https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html#section-14.3.2).

**Impact**

A previously valid presentation may be replayed or assigned to another known session. A valid credential intended for another Verifier or transaction may be accepted.

**Required fix**

Before cryptographic verification, load exactly one pending session using the route ID and validate atomically:

- The form `state` exactly equals the stored state and route ID.
- The session exists, is pending, and has not expired.
- The presentation's format-specific nonce equals the session nonce.
- The presentation's format-specific audience equals the full expected `client_id`, including its prefix.
- The session has not already been consumed.

Mark the session consumed in the same database transaction that stores the successful result. Never select the target session from an unvalidated response value.

**Acceptance criteria**

- Wrong route ID, state, nonce, or audience is rejected.
- An expired session is rejected.
- Replaying the same response is rejected, including under concurrency.
- A rejected response never writes or overwrites a successful result.

### C-03 — The request nonce stored in the database is not the nonce sent to the Wallet

**Evidence**

- [`DBService.cs:26`](api/VerifierAPI/Service/DBService.cs#L26) creates and stores a six-character nonce.
- [`VerifierController.cs:378`](api/VerifierAPI/Controllers/VerifierController.cs#L378) ignores that value and sends the session ID as `nonce`.
- [`VerifierController.cs:83`](api/VerifierAPI/Controllers/VerifierController.cs#L83) returns the different stored nonce to the caller.

OpenID4VP requires a fresh cryptographically random nonce with sufficient entropy to be stored with the session and sent in the Authorization Request. See [§5.2](https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html#section-5.2).

**Impact**

The database cannot be used to validate the nonce actually sent to the Wallet. The six-character value also has insufficient entropy for a security nonce.

**Required fix**

Generate one URL-safe nonce of at least 128 bits, store that exact value, and use that exact value in the request and response validation. Do not reuse `state` as `nonce` even when both happen to be random.

**Acceptance criteria**

- Stored nonce equals request nonce byte-for-byte.
- Nonce and state are independent random values.
- Both are single-use and URL-safe.

### C-04 — SD-JWT VC verification is incomplete and unsafe

**Evidence**

- [`VerifierController.cs:468`](api/VerifierAPI/Controllers/VerifierController.cs#L468) removes disclosures and the Key Binding JWT before initial verification.
- [`VerifierController.cs:515`](api/VerifierAPI/Controllers/VerifierController.cs#L515) verifies only the issuer-signed JWT portion.
- [`VCService.cs:755`](api/VerifierAPI/Service/VCService.cs#L755) parses disclosures and a KB-JWT but only calls `VerifyJWS()` on the issuer JWT.
- [`VerifierController.cs:710`](api/VerifierAPI/Controllers/VerifierController.cs#L710) decodes disclosure values for display without first proving that their digests are included in the signed `_sd` structure.

The code does not validate disclosure digests, the KB-JWT signature, holder-key binding, `sd_hash`, KB-JWT `nonce`, KB-JWT `aud`, or presentation time constraints. See [Appendix B.3.6](https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html#appendix-B.3.6).

**Impact**

The Verifier may accept an issuer-signed SD-JWT without proof that the presenter controls the holder key. Unverified disclosure data may be shown or stored as trusted claims.

**Required fix**

Disable `dc+sd-jwt` immediately. Re-enable it only with one complete verifier that validates the entire combined SD-JWT presentation according to the specification version referenced by OpenID4VP 1.0. Do not separately trust decoded disclosures.

**Acceptance criteria**

- Missing or invalid KB-JWT is rejected when holder binding is required.
- Modified, injected, or removed disclosures are detected.
- Wrong `sd_hash`, nonce, audience, holder key, or algorithm is rejected.

### C-05 — Secrets and credential/session data are committed to source control

**Evidence**

- [`appsettings.json`](api/VerifierAPI/appsettings.json) contains a client secret.
- [`api/.env`](api/.env) and Docker Compose files contain environment/database secrets.
- [`init.sql`](api/db/init.sql) contains populated verifier sessions and captured VP/VC payloads rather than schema-only seed data.

**Impact**

Secrets must be considered compromised. Captured presentations can contain personal data and cryptographic material, creating privacy, incident-response, and regulatory risk.

**Required fix**

1. Rotate every committed secret immediately.
2. Remove secrets and captured data from the current tree and Git history.
3. Keep only placeholders and schema-safe synthetic fixtures.
4. Load deployment secrets from an approved secret store or environment variables.
5. Review repository access and logs as part of an incident assessment.

**Acceptance criteria**

- Secret scanning reports no active credentials.
- Database seeds contain no real presentations, credentials, users, or sessions.
- Rotated credentials are not derivable from repository history.

## High-severity defects

### H-01 — `request_uri` returns an unsecured `alg: none` Request Object

**Evidence**

- [`VerifierController.cs:369`](api/VerifierAPI/Controllers/VerifierController.cs#L369) implements a Request URI endpoint.
- [`VerifierController.cs:405`](api/VerifierAPI/Controllers/VerifierController.cs#L405) returns a JWT using `alg: none`.
- [`VerifierController.cs:87`](api/VerifierAPI/Controllers/VerifierController.cs#L87) simultaneously chooses the `redirect_uri:` Client Identifier Prefix.

A Request Object returned by reference must be signed. However, the `redirect_uri:` prefix cannot be used for signed requests because the Wallet has no trusted key-discovery mechanism for that prefix. See [§5.9.3](https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html#section-5.9.3) and [§5.10.1](https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html#section-5.10.1).

**Required fix**

Choose one valid mechanism:

- Minimal option: keep `redirect_uri:` and place the unsigned, URL-encoded request parameters directly in the authorization URI; do not use `request_uri`.
- Signed option: adopt a Client Identifier Prefix with defined request authentication and key discovery, then create and validate a signed Request Object accordingly.

**Acceptance criteria**

- No Request Object uses `alg: none`.
- The chosen request mechanism is permitted by its Client Identifier Prefix.

### H-02 — W3C `jwt_vc_json` DCQL `type_values` has the wrong shape

**Evidence**

[`VCService.cs:874`](api/VerifierAPI/Service/VCService.cs#L874) emits `type_values` as an array containing one string. Final OpenID4VP requires a non-empty array of non-empty string arrays. See [Appendix B.1.1](https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html#appendix-B.1.1).

**Required fix**

Emit:

```json
"type_values": [["VerifiableCredential", "IDCardCredential"]]
```

Use fully expanded type IRIs where required by the credential's JSON-LD contexts.

**Acceptance criteria**

- Generated DCQL passes schema tests for every configured document type.
- A conforming Wallet can evaluate each query.

### H-03 — SD-JWT metadata uses the wrong algorithm parameter

**Evidence**

[`VerifierController.cs:383`](api/VerifierAPI/Controllers/VerifierController.cs#L383) emits generic `alg_values` for every credential format.

For `dc+sd-jwt`, the relevant fields are `sd-jwt_alg_values` and `kb-jwt_alg_values`. See [Appendix B.3.4](https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html#appendix-B.3.4).

**Required fix**

Build format-specific metadata. Do not reuse the W3C JWT metadata shape for SD-JWT VC or mdoc.

### H-04 — Returned presentations are not validated against the stored DCQL request

**Evidence**

The response code verifies signatures but never checks the returned Credential Query ID, requested format, type/VCT, requested claims, `credential_sets`, or original document type. It instead infers a display route from the returned `vct` at [`VerifierController.cs:581`](api/VerifierAPI/Controllers/VerifierController.cs#L581).

OpenID4VP requires each presentation and the complete returned set to satisfy the original query. See [§8.6](https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html#section-8.6).

**Required fix**

Persist the exact normalized DCQL query with the session. After format-specific cryptographic verification, evaluate the verified claims and credential metadata against that stored query. Never select policy from untrusted response content.

### H-05 — JWS verification is hard-coded to Ed25519

**Evidence**

- [`VCService.cs:244`](api/VerifierAPI/Service/VCService.cs#L244) always imports an Ed25519 public key.
- [`init.sql:50`](api/db/init.sql#L50) advertises ES256 for ID card and driver-license configurations.

**Impact**

Advertised ES256 credentials cannot be verified correctly, while the verifier does not enforce that the received `alg` matches the algorithm permitted for the selected format/query.

**Required fix**

Read and validate the protected `alg` header, reject `none` and algorithms outside the stored allowlist, and use the matching cryptographic verifier and key type. Do not infer algorithms solely from key length or DID method.

### H-06 — DID key selection ignores the full `kid`

**Evidence**

- [`VCService.cs:218`](api/VerifierAPI/Service/VCService.cs#L218) reads `kid` but strips its fragment for resolution.
- [`VCService.cs:153`](api/VerifierAPI/Service/VCService.cs#L153) iterates all verification methods and leaves the final key as the selected key.

**Impact**

The signature may be checked with a key other than the verification method identified by the signed JOSE header. Key purpose, curve, algorithm, and authorization relationship are not checked.

**Required fix**

Resolve the DID document, then select exactly the verification method whose full ID equals `kid`. Validate key type, algorithm, proof purpose, and controller. Reject zero or multiple matches.

### H-07 — Session expiry and one-time-use fields are not enforced

**Evidence**

- [`DBService.cs:34`](api/VerifierAPI/Service/DBService.cs#L34) stores `ExpiresAt`.
- The response endpoint never reads it.
- A `usednonce` table exists in [`init.sql:198`](api/db/init.sql#L198), but no active verification path uses it.

**Required fix**

Use the session row itself as the single source of truth: `Pending`, `Consumed`, or `Failed`, with expiry checked and successful consumption performed atomically. A separate nonce table is unnecessary unless another protocol consumer requires it.

### H-08 — Verifier result endpoints disclose credentials without authorization

**Evidence**

- [`VerifierController.cs:651`](api/VerifierAPI/Controllers/VerifierController.cs#L651) returns VP and VC payloads for a supplied session ID.
- Neither this endpoint nor the status endpoints require authorization.

**Impact**

Anyone who obtains or guesses a session ID may retrieve identity data. Session IDs are exposed in QR/request flows and must not be treated as access tokens.

**Required fix**

Require authenticated, authorized access tied to the originating verifier/operator session. Return only the minimum verified claims needed by the application; do not return raw VP/VC tokens by default.

### H-09 — Full presentations and keys are written to logs

**Evidence**

[`VerifierController.cs:452`](api/VerifierAPI/Controllers/VerifierController.cs#L452), [`VerifierController.cs:492`](api/VerifierAPI/Controllers/VerifierController.cs#L492), and [`VerifierController.cs:526`](api/VerifierAPI/Controllers/VerifierController.cs#L526) log full VP/VC material and resolved public-key values.

**Required fix**

Remove token, disclosure, credential, claim, and key-value logging. Log a generated correlation ID, outcome, format, and non-sensitive error code. Apply retention and access controls to remaining security logs.

### H-10 — Broker URL validation does not require HTTPS or constrain the complete origin

**Evidence**

[`VerifierRequestService.cs:28`](api/VerifierAPI/Service/VerifierRequestService.cs#L28) accepts any absolute URI, and [`VerifierRequestService.cs:35`](api/VerifierAPI/Service/VerifierRequestService.cs#L35) checks only the host name. Scheme, port, userinfo, redirects, and final redirect destination are not constrained.

OpenID4VP requires current TLS best practices and certificate validation. See [§14.6](https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html#section-14.6).

**Required fix**

Allowlist exact HTTPS origins, reject userinfo and unexpected ports, and disable automatic redirects or revalidate every redirect target against the same allowlist. Apply short timeouts and response-size limits.

## Medium-severity defects

### M-01 — Authorization Error Responses are not supported

The `direct_post` endpoint requires `vp_token` and `state` parameters and has no model for `error`, `error_description`, or `error_uri`. A legitimate Wallet error therefore becomes model-binding failure rather than a processed Authorization Error Response.

**Recommendation:** accept either a success response or an error response, never both; validate state for both; store a safe failure code; and return the JSON response required by [§8.2](https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html#section-8.2).

### M-02 — The returned `redirect_uri` lacks a fresh response code

[`VerifierController.cs:594`](api/VerifierAPI/Controllers/VerifierController.cs#L594) returns a URL containing the request state, which was already disclosed to the Wallet, rather than a newly generated response secret.

**Recommendation:** if using a post-response redirect, generate a new random response code after accepting the response, bind it to the stored result, make it single-use and short-lived, and require it when the frontend fetches the result. See [§14.2](https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html#section-14.2).

### M-03 — Duplicate status routes create ambiguous behavior

Both [`VerifierController.cs:685`](api/VerifierAPI/Controllers/VerifierController.cs#L685) and [`VerifierScanController.cs:74`](api/VerifierAPI/Controllers/VerifierScanController.cs#L74) register `GET /verifier/status/{sessionId}` with different implementations.

**Recommendation:** keep one endpoint and delete the duplicate. Return explicit `pending`, `completed`, `failed`, and `expired` states based on the verified session status.

### M-04 — Status currently treats stored data as successful verification

[`VerifierScanController.cs:89`](api/VerifierAPI/Controllers/VerifierScanController.cs#L89) explicitly notes that any row containing payload data is treated as completed. The parallel endpoint has the same behavior.

**Recommendation:** store an explicit verification result only after all protocol, cryptographic, DCQL, trust, validity, and policy checks pass. Never infer validity from payload presence.

### M-05 — `client_id`, request URI, and response URI are built from untrusted request host data

Several paths use `Request.Scheme` and `Request.Host` directly, for example [`VerifierController.cs:377`](api/VerifierAPI/Controllers/VerifierController.cs#L377). Incorrect proxy configuration or Host-header handling can produce a malicious or non-public URI.

**Recommendation:** configure one canonical external HTTPS base URI, validate it at startup, and use it for all externally visible protocol values. Do not construct security identifiers from arbitrary request headers.

### M-06 — The Request URI endpoint does not enforce session existence or expiry

[`VerifierController.cs:380`](api/VerifierAPI/Controllers/VerifierController.cs#L380) may receive a missing session/document type and then dereference it. Repeated requests remain available until database cleanup, regardless of expiry.

**Recommendation:** return a protocol-safe error for missing, expired, consumed, or invalid request IDs. Do not reveal whether unrelated IDs exist beyond what the protocol requires.

### M-07 — The published TypeScript SDK contains no implementation

[`sdk/src/index.ts`](sdk/src/index.ts) is empty, while [`sdk/package.json`](sdk/package.json) declares version `1.0.0` and has no real test command.

**Recommendation:** either remove/rename the SDK claim and document that this repository contains only an API prototype, or implement and test an actual public SDK contract. Do not publish an empty `1.0.0` package.

### M-08 — Duplicated and excluded implementations obscure the active protocol path

The project contains `VerifierRequestService.cs`, `VerifierRequestService(1).cs`, multiple document-type registries/models, dead commented flows, and unused validation helpers. The project file excludes one duplicate by filename.

**Recommendation:** delete excluded, dead, and unused protocol implementations after preserving any required history in Git. Keep one request generator, one session model, one DCQL builder, and one verification pipeline. This reduces the risk of fixing an inactive copy.

## Format support assessment

| Format | Current claim/configuration | Audit result | Required action |
|---|---|---|---|
| `jwt_vc_json` | Configured | Not compliant: final response shape, DCQL shape, algorithm selection, audience/nonce, and query checks are missing | Implement first as the only enabled format |
| `dc+sd-jwt` | Configured | Unsafe: issuer signature only; disclosures and holder binding are incomplete | Disable until complete SD-JWT VC verification exists |
| `mso_mdoc` | Present in JSON/registry code | No active DeviceResponse/CBOR, IssuerAuth, DeviceAuth, or SessionTranscript verifier | Remove from advertised support until fully implemented |

## Recommended remediation plan

### Phase 0 — Immediate containment

1. Rotate and remove committed secrets.
2. Remove captured VP/VC/session data from Git history.
3. Disable SD-JWT VC and mdoc configuration.
4. Disable public raw-token/result endpoints.
5. Remove full credential/token logging.

### Phase 1 — One minimal compliant flow

Implement only `jwt_vc_json` with `response_type=vp_token` and `response_mode=direct_post`:

1. Generate independent 128-bit-or-greater `state` and `nonce` values.
2. Store the exact request, expected full `client_id`, DCQL, nonce, state, expiry, and status.
3. Use direct encoded request parameters with the `redirect_uri:` prefix; remove the unsecured Request Object.
4. Parse the final `vp_token` object.
5. Validate state/session before processing credentials.
6. Verify the VP and VC signatures using exact `kid` selection and permitted algorithms.
7. Validate VP `nonce` and `aud` exactly.
8. Validate holder binding, credential time validity, issuer trust/revocation policy, and the complete DCQL result.
9. Atomically store the verified result and consume the session.
10. Return the required JSON `direct_post` response.

### Phase 2 — Tests and interoperability

Add the smallest useful automated suite at the public protocol boundary. It must cover:

- Valid final-format response.
- Wrong/missing state.
- Wrong/missing nonce.
- Wrong/missing audience.
- Expired session.
- Replay and concurrent replay.
- Unknown DCQL credential ID.
- Missing required credential query.
- Wrong type/VCT, format, claims, or algorithm.
- Invalid VP signature and invalid VC signature.
- Unknown or mismatched `kid`.
- Wallet Authorization Error Response.
- Rejection of legacy bare-JWS and bare-array responses.

Run clean builds on Linux and in CI; do not commit `bin/`, `obj/`, local `.env`, user files, or generated package assets.

### Phase 3 — Additional formats

Add one format at a time only after its complete verification path and negative test vectors exist:

- For SD-JWT VC: disclosure digests, KB-JWT, holder key, `sd_hash`, nonce, audience, algorithms, validity, and query evaluation.
- For mdoc: DeviceResponse CBOR, issuer authentication, device authentication, certificate/trust validation, validity, requested namespaces/elements, and the exact OpenID4VP SessionTranscript/Handover binding.

## Definition of done

The project should not describe itself as OpenID4VP 1.0 compliant until all of the following are true:

- Every Critical and High finding above is closed with automated negative tests.
- Unsupported formats are not advertised.
- A clean checkout builds and tests without machine-specific assets.
- Secrets and personal credential data are absent from the repository and its distributed history.
- At least two independent conforming Wallet implementations interoperate with the Verifier.
- The implementation passes the applicable OpenID Foundation conformance tests or an equivalent independently reviewed suite.
- A security review confirms replay prevention, transaction binding, holder binding, trust policy, privacy controls, and result-access authorization.

## Primary specification references

- [Authorization Request and nonce requirements (§5)](https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html#section-5)
- [Client Identifier Prefixes (§5.9)](https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html#section-5.9)
- [DCQL (§6)](https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html#section-6)
- [Response and `vp_token` structure (§8)](https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html#section-8)
- [`direct_post` response mode (§8.2)](https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html#section-8.2)
- [VP Token validation (§8.6)](https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html#section-8.6)
- [Replay prevention and transaction binding (§14.1)](https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html#section-14.1)
- [W3C VC format rules (Appendix B.1)](https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html#appendix-B.1)
- [mdoc format rules (Appendix B.2)](https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html#appendix-B.2)
- [SD-JWT VC format rules (Appendix B.3)](https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html#appendix-B.3)

