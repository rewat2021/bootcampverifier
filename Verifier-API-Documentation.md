# Verifier API Documentation

**Project:** `verifier-sdk` (`bootcamp_verifier` / `VerifierAPI`)
**Protocol:** OpenID for Verifiable Presentations (OpenID4VP) 1.0 Final
**Generated:** 2026-08-23

> This document is generated directly from the current controller source code (`Controllers/*.cs`), not from a live Swagger/OpenAPI export — the deployed server (`https://verifier.zenithcomp.co.th:455`) was not reachable from the environment that produced this document. Swagger UI is still available at `/swagger` on the running app itself (configured in `Program.cs`) if you need the live, auto-generated spec.

---

## Overview

### Base URLs

| Context | Value |
|---|---|
| Public base URL | `https://verifier.zenithcomp.co.th:455` |
| Internal base URL (container-to-container) | `http://verifier-api:8080` (`INTERNAL_BASE_URL` env var) |

### Content types

- Most protocol endpoints (`/openid4vc/...`) accept/return **JSON**, except `POST /openid4vc/verify/{id}` which accepts **`application/x-www-form-urlencoded`** (per OpenID4VP `direct_post`) and `GET /openid4vc/request/{id}` which returns **`application/oauth-authz-req+jwt`** (a raw JWT string, not JSON).
- All JSON bodies (request and response) use **snake_case property names** — the app is globally configured with `JsonNamingPolicy.SnakeCaseLower` (`Program.cs`). A C# property like `AuthorizationRequestUri` serializes as `authorization_request_uri`.
- `POST /verifier/scan` is forced to `text/plain` output (`[Produces("text/plain")]`) regardless of `Accept` header — its body is either the raw `openid4vp://` URI or a bare error-code string, never a JSON envelope.

### Authentication

| Scheme | Used by | Notes |
|---|---|---|
| None (public) | All `/openid4vc/*` protocol endpoints, `POST /verifier/scan` | Called directly by the Wallet or a QR-scanning terminal — no login. |
| Cookie (ThaID-backed) | `/verifier/status/{id}`, `/VerifyScanQR`, `/PresentResult/VerifyResult`, `/AuditLog`, `POST /Account/Logout` | ASP.NET Cookie auth (`CookieAuthenticationDefaults`), issued via `/Account/ThaIDSignIn` after a ThaID round trip. Login path: `/Account/ThaIDLogin`. Unauthenticated requests under `/verifier/*` get a clean `401`; everywhere else they get a `302` redirect to the login page. |
| None (protected by an unguessable code instead) | `GET /PresentResult/Result/{responseCode}` | Deliberately `[AllowAnonymous]` — this is the page the Holder's own Wallet browser lands on right after presenting, so it can't require an operator's ThaID login. Protected instead by a fresh, single-purpose, 256-bit random `response_code` with a 30-minute validity window. |

### Common error response shape

Failure responses from the `/openid4vc/*` protocol endpoints generally follow:

```json
{
  "error": "invalid_request <short machine context>",
  "error_description": "Present VP is invalid",
  "reason": "<machine-readable error code, e.g. disclosure_digest_mismatch>"
}
```

`reason` is present on most (not all) failure paths — see each endpoint below for what values it can take.

---

## 1. OpenID4VP Protocol Endpoints

Controller: `VerifierController` — route prefix `openid4vc`. These are the actual OpenID4VP wire-protocol endpoints; the Wallet talks to `request/{id}` and `verify/{id}` directly.

### 1.1 `POST /generate-vp-qr`

Creates a new verification session and returns a QR-encodable Authorization Request URI (by reference — `client_id` + `request_uri`).

**Auth:** none
**Request body** (JSON):

```json
{
  "document_type": "Transcript"
}
```

`document_type` is one of: `Transcript`, `IDCard`, `DriverLicense`, `Bootcamp`.

**Response — `200 OK`:**

```json
{
  "authorization_request_uri": "openid4vp://authorize?client_id=...&request_uri=...",
  "deeplink_uri": "walletapp://callback?client_id=...&request_uri=...",
  "qr_text": "openid4vp://authorize?client_id=...&request_uri=...",
  "qr_image_base64": "<base64 PNG, no data: prefix>",
  "state": "<session id, GUID>",
  "nonce": "<43-char base64url, 256-bit random>"
}
```

`qr_text` / `authorization_request_uri` is meant to be rendered as a QR code and scanned cross-device; `deeplink_uri` is for a same-device "open wallet" button.

---

### 1.2 `GET /openid4vc/request/{id}`

The Request URI endpoint — what the Wallet dereferences after receiving `client_id` + `request_uri` from step 1.1. Returns a **signed** OpenID4VP Request Object (ES256/P-256, `client_id` prefix `decentralized_identifier:did:key:...`, per §5.9.3).

**Auth:** none
**Path parameter:** `id` — the session id returned as `state` from `/generate-vp-qr`.

**Response — `200 OK`**, `Content-Type: application/oauth-authz-req+jwt`, body is a raw compact JWS (not JSON):

```
eyJhbGciOiJFUzI1NiIsInR5cCI6Im9hdXRoLWF1dGh6LXJlcSt...
```

Decoded payload shape:

```json
{
  "response_type": "vp_token",
  "client_id": "decentralized_identifier:did:key:zDna...",
  "response_mode": "direct_post",
  "state": "<session id>",
  "dcql_query": { "credentials": [ { "id": "...", "format": "...", "meta": {...}, "claims": [...] } ] },
  "client_metadata": { "vp_formats_supported": { "...": {...} } },
  "nonce": "<session nonce>",
  "response_uri": "https://.../openid4vc/verify/<session id>"
}
```

**Response — `404 Not Found`:** unknown document type for the session, or the session doesn't exist / has expired (`ExpiresAt < now`).

---

### 1.3 `POST /openid4vc/verify/{id}`

The `response_uri` the signed Request Object points to — the Wallet's `direct_post` Authorization Response lands here.

**Auth:** none
**Path parameter:** `id` — session id (must equal the `state` form field).
**Request body** (`application/x-www-form-urlencoded`):

| Field | Required | Notes |
|---|---|---|
| `state` | yes | Must match the session id in the path. |
| `vp_token` | conditionally | Required unless `error` is present. Final-shape JSON object (`{"<dcql id>": ["<jws-or-sd-jwt>"]}`) is the supported shape; a bare JSON array is still accepted for legacy Wallets. |
| `error` | no | Wallet Authorization Error Response — mutually exclusive with `vp_token`. |
| `error_description` | no | Only meaningful alongside `error`. |
| `error_uri` | no | Accepted, not currently used further. |
| `device_engagement` | mso_mdoc only | Base64url CBOR — required when the session's document type is `mso_mdoc` (NFC proximity flow). |
| `e_reader_key` | mso_mdoc only | Base64url CBOR, same condition as above. |
| `handover_select` | mso_mdoc only | Base64url CBOR, same condition as above. |
| `handover_request` | mso_mdoc only | Base64url CBOR, optional even for mso_mdoc. |

**Response — `200 OK`:**

```json
{ "redirect_uri": "https://.../PresentResult/Result/<response_code>" }
```

`response_code` is a fresh, single-purpose 256-bit random value generated on every successful response — not the session id.

**Response — `400 Bad Request`:** see the common error shape above. Selected `reason` values you may see:

| `reason` | Meaning |
|---|---|
| `vp_signature_invalid` | Outer VP / issuer JWS signature did not verify (bad key, wrong alg, DID resolution failed). |
| `disclosure_digest_mismatch` | A disclosed SD-JWT claim's digest isn't in the credential's signed `_sd`. |
| `missing_kb_jwt` / `invalid_kb_jwt_signature` | SD-JWT Key Binding JWT missing or its signature didn't verify. |
| `sd_hash_mismatch` | KB-JWT `sd_hash` doesn't match the presented issuer-JWT + disclosure set. |
| `nonce_mismatch` / `audience_mismatch` | `nonce`/`aud` (VP-JWT or KB-JWT) doesn't match this session. |
| `credential_expired` / `credential_not_yet_valid` | Credential's own `nbf`/`exp` fails validity. |
| `unexpected_credential_format` / `unexpected_credential_type` | Returned credential doesn't match this session's stored DCQL query. |
| `malformed_engagement_bytes` / `missing_engagement_bytes` | mso_mdoc proximity fields missing/undecodable. |
| (Wallet's own `error` code, e.g. `access_denied`) | Wallet declined/failed the request — passed through verbatim. |

Every failure path also marks the session `Failed` (distinguishable via `GET /verifier/status/{id}`, §2.2). A session can only be answered once — replaying a response against an already-`Consumed` or already-`Failed` session (or an expired one) is rejected with `error: "invalid_request reject" / "invalid_request expire"` before any cryptographic work happens.

---

### 1.4 `GET /openid4vc/vp/{id}` — **disabled**

**Response — `410 Gone`:**

```json
{
  "error": "endpoint_disabled",
  "error_description": "This endpoint has been disabled pending authorization controls (see H-08 in the compliance audit)."
}
```

Previously returned the raw stored VP/VC token for any session id with no authorization check. Left in the codebase only as a stub that always returns `410`.

---

## 2. QR Scan / Broker Endpoints

Controller: `VerifierScanController` — route prefix `verifier`. Used by an operator-facing scanning terminal (laser/QR reader) that relays a scanned code to a broker service, which in turn drives the Wallet.

### 2.1 `POST /verifier/scan`

**Auth:** Cookie (`[Authorize]` on the controller) — called from the operator's own authenticated browser session (`VerifyScanQR.cshtml`'s JS), not by the Wallet.
**Produces:** `text/plain` (always — see Overview)
**Request body** (JSON):

```json
{
  "scanned_value": "https://broker.example/broker/session/<id>/request",
  "doc_type": "DriverLicense"
}
```

**Responses:**

| Status | Body | Meaning |
|---|---|---|
| `200` | `openid4vp://authorize?client_id=...&request_uri=...` | Broker accepted the relayed request; hand this URI to the Wallet. |
| `400` | `empty_scanned_value` | `scanned_value` missing from the request body. |
| `400` | `doc_type_required` | `doc_type` missing from the request body. |
| `400` | `invalid_qr_content` | Scanned value isn't a valid absolute URI, or session id couldn't be extracted from its path (expected shape `.../session/{sessionId}/...`). |
| `400` | `unknown_doc_type` | `doc_type` doesn't match a configured document type. |
| `403` | `untrusted_broker_endpoint` | Scanned URL fails the broker allowlist check — host not in `AllowedBrokerHosts` or port not in `AllowedBrokerPorts` (`appsettings.json`). |
| `502` | `broker_unreachable` | Network error calling the broker. |
| `500` | other | Broker responded with a non-success status, or an unclassified error. |

---

### 2.2 `GET /verifier/status/{sessionId}`

Polling endpoint for the operator's UI to find out whether the Wallet has responded yet.

**Auth:** Cookie (`[Authorize]`)
**Path parameter:** `sessionId`

**Response — `200 OK`:**

```json
{ "status": "pending" }
```
```json
{ "status": "completed", "claims": { "family_name": "...", "given_name": "..." }, "response_code": "<code>" }
```
```json
{ "status": "failed", "error": "verification_failed" }
```
```json
{ "status": "expired" }
```
```json
{ "status": "unknown" }
```

`status` reflects the session row's own `Status` column (`Pending` / `Consumed` / `Failed`) plus expiry — not just "is there a response row", so a failed verification is reported as `failed` immediately rather than staying `pending` until the session times out (fixed under compliance-audit finding M-04). `claims` (only present on `completed`) is a best-effort decode of the stored VC payload's disclosed claims, for display only — not re-verified at this point.

---

## 3. Result & Operator Pages

Controller: `PresentResultController`. These render server-side HTML (Razor views), not JSON — listed here because they're still part of the reachable HTTP surface.

### 3.1 `GET /PresentResult/Result/{responseCode}`

**Auth:** none (`[AllowAnonymous]` — see Overview for why)
The page the Holder's Wallet browser is redirected to after §1.3 succeeds. Looks up the result by `response_code` (not session id), valid for 30 minutes from `ReceivedAt`. Renders the decoded VP/VC claims. Returns a "not found" view (still `200`) if the code is unknown or expired.

### 3.2 `GET /PresentResult/VerifyResult`

**Auth:** Cookie (`[Authorize]`)
Self-service landing page for a ThaID-authenticated operator/user (distinct from the Wallet-facing page above).

### 3.3 `GET /VerifyScanQR`

**Auth:** Cookie (`[Authorize]`)
The operator's QR-scanning terminal UI — drives §2.1/§2.2 via JavaScript (`fetch`), including a keyboard-wedge HID scanner listener.

---

## 4. Authentication

Controller: `AccountController`. Two parallel login mechanisms exist: a legacy username/password form, and ThaID (the one actually used operationally).

### 4.1 `GET /Account/Login`

**Auth:** none — renders the login form. Query: `ReturnUrl` (optional).

### 4.2 `POST /Account/Login`

**Auth:** none, `[ValidateAntiForgeryToken]`
**Body:** form fields `username`, `password`, `ReturnUrl` (optional).
On success, issues the auth cookie and redirects to `ReturnUrl` (if a local URL) or `PresentResult/VerifyResult`. On failure, re-renders the form with a validation error.

### 4.3 `POST /Account/Logout`

**Auth:** Cookie (`[Authorize]`) — signs the cookie out, redirects to `Login`.

### 4.4 `GET /Account/AccessDenied`

**Auth:** none — static "access denied" view, used as the Cookie auth scheme's `AccessDeniedPath`.

### 4.5 `GET /Account/ThaIDSignIn`

**Auth:** none — this is the redirect target ThaID's gateway calls back to.
**Query:** `pid` (required — the verified citizen id from ThaID), `ReturnUrl` (optional).
Issues the auth cookie from `pid` directly (ThaID has already verified identity), then redirects — preferring `ReturnUrl`, falling back to a `ReturnUrl` stashed earlier in the `thaiid_pending_return` cookie (see 4.7), finally falling back to `PresentResult/VerifyResult`.

### 4.6 `GET /Account/ThaIDLogin`

**Auth:** none — renders a view with `ReturnUrl`/`documentType` in `ViewBag` for a hidden form field. Query: `ReturnUrl`, `documentType` (both optional).

### 4.7 `GET /thaiid/login`

**Auth:** none — this is the actual "start ThaID login" action (note the distinct lowercase route, separate from 4.6's action of almost the same name).
**Query:** `returnUrl`, `documentType`, `error` (all optional).
Stashes `{returnUrl, documentType}` in a short-lived, `HttpOnly`+`Secure` cookie (`thaiid_pending_return`, 10-minute expiry — needed because the ThaID gateway's own callback doesn't round-trip custom parameters), then `302`s to the ThaID gateway (`ThaIDConfig.GatewayBaseUrl`) with `clientid`, `role=verifier`, `documentType`.

---

## 5. Audit Log

Controller: `AuditLogController`.

### 5.1 `GET /AuditLog`

**Auth:** Cookie (`[Authorize]`)
**Query:** `page` (default `1`), `status` (optional — `success` or `failed`, anything else is ignored as a filter).
Server-rendered, paginated (50/page) view over `dbverifierlog` — one row is written per `POST /openid4vc/verify/{id}` call (via `VerifierAuditLogFilter`), success or failure, including the error reason, requester IP, and User-Agent. Not publicly viewable — shows identity-adjacent operational data.

---

## Appendix A — Session status lifecycle

Every session (`Dbverifiersession`) created by `POST /generate-vp-qr` moves through:

```
Pending ──(Wallet responds, verification passes)──▶ Consumed
   │
   ├──(Wallet responds, verification fails, any reason)──▶ Failed
   │
   └──(ExpiresAt elapses with no response)──▶ (stays Pending; reported as "expired" by §2.2)
```

A session can only leave `Pending` once — both `Consumed` and `Failed` reject any further `POST /openid4vc/verify/{id}` call against the same session id (replay protection).

## Appendix B — `vp_token` response shape (final OpenID4VP §8.1)

```json
{
  "<dcql-credential-query-id>": ["<jws-or-sd-jwt-presentation>"]
}
```

Each key is a Credential Query `id` from the session's stored `dcql_query`; each value is an array of one or more matching Presentations. A legacy bare `["<jws>"]` array is still accepted for older Wallet builds.

## Appendix C — DCQL query examples (as sent in §1.2's Request Object)

`dc+sd-jwt`:

```json
{
  "credentials": [
    {
      "id": "driverlicense_credential",
      "format": "dc+sd-jwt",
      "meta": { "vct_values": ["https://issuer.example/credentials/DriverLicense"] },
      "claims": [
        { "path": ["family_name"] },
        { "path": ["given_name"] },
        { "path": ["birth_date"] },
        { "path": ["document_number"] },
        { "path": ["issue_date"] },
        { "path": ["expiry_date"] },
        { "path": ["resident_address"] },
        { "path": ["driving_privileges"] },
        { "path": ["portrait"] }
      ]
    }
  ]
}
```

`jwt_vc_json`:

```json
{
  "credentials": [
    {
      "id": "idcard_credential",
      "format": "jwt_vc_json",
      "meta": { "type_values": [["VerifiableCredential", "IDCardCredential"]] }
    }
  ]
}
```

`mso_mdoc`:

```json
{
  "credentials": [
    {
      "id": "driverlicense_credential",
      "format": "mso_mdoc",
      "meta": { "doctype_value": "org.iso.18013.5.1.mDL" }
    }
  ]
}
```

## Appendix D — Notes for API consumers

- Treat `nonce` and `state` returned from §1.1 as single-use, session-scoped values — they cannot be reused across sessions.
- `response_code` (from §1.3's `redirect_uri`) is the only thing that gates access to the result page (§3.1); it is not a session id and is deliberately unpredictable — do not attempt to derive or guess it.
- The `/openid4vc/*` endpoints have no rate limiting or CORS restriction beyond the configured `AllowedBrokerHosts`/CORS policy in `Program.cs` — they are meant to be called by Wallets over the open internet, per the OpenID4VP protocol model.
- `GET /openid4vc/request/{id}` and `POST /openid4vc/verify/{id}` are one-shot per session; do not poll or retry them against the same session id expecting different behavior once a terminal state (`Consumed`/`Failed`) is reached.

## Appendix E — Open compliance items (not part of the wire API, noted for completeness)

- **C-05 (open):** `appsettings.json` still stores the ThaID `ClientSecret` in plaintext. Not yet rotated/externalized — flagged in `OID4VP-1.0-COMPLIANCE-AUDIT.md`, no action taken pending confirmation.
- **`direct_post.jwt` (not implemented):** only plain `direct_post` is currently supported as the Authorization Response mode; encrypted responses would require adding a Verifier encryption keypair and JWE decryption to §1.3.
