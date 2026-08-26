# เอกสาร API ของ Verifier

**โปรเจกต์:** `verifier-sdk` (`bootcamp_verifier` / `VerifierAPI`)
**โปรโตคอล:** OpenID for Verifiable Presentations (OpenID4VP) 1.0 Final
**วันที่จัดทำ:** 2026-08-23

> เอกสารนี้จัดทำจากซอร์สโค้ด controller ปัจจุบัน (`Controllers/*.cs`) โดยตรง ไม่ได้ export มาจาก Swagger/OpenAPI จริง เนื่องจาก server ที่ deploy ไว้ (`https://verifier.zenithcomp.co.th:455`) ไม่สามารถเข้าถึงได้จาก environment ที่ใช้จัดทำเอกสารนี้ อย่างไรก็ตาม Swagger UI ยังเปิดใช้งานอยู่ที่ path `/swagger` บนแอปที่รันจริง (ตั้งค่าไว้ใน `Program.cs`) หากต้องการ spec ที่ auto-generate แบบสด

---

## ภาพรวม

### Base URL

| บริบท | ค่า |
|---|---|
| Public base URL | `https://verifier.zenithcomp.co.th:455` |
| Internal base URL (container-to-container) | `http://verifier-api:8080` (env var `INTERNAL_BASE_URL`) |

### รูปแบบ Content-Type

- endpoint ส่วนใหญ่ในกลุ่มโปรโตคอล (`/openid4vc/...`) รับ/ส่งข้อมูลเป็น **JSON** ยกเว้น `POST /openid4vc/verify/{id}` ซึ่งรับข้อมูลแบบ **`application/x-www-form-urlencoded`** (ตาม `direct_post` ของ OpenID4VP) และ `GET /openid4vc/request/{id}` ซึ่งส่งกลับเป็น **`application/oauth-authz-req+jwt`** (raw JWT string ไม่ใช่ JSON)
- JSON body ทั้งหมด (ทั้ง request และ response) ใช้ชื่อ property แบบ **snake_case** — แอปตั้งค่า `JsonNamingPolicy.SnakeCaseLower` ไว้แบบ global (`Program.cs`) ดังนั้น property ใน C# เช่น `AuthorizationRequestUri` จะถูก serialize เป็น `authorization_request_uri`
- `POST /verifier/scan` ถูกบังคับให้ตอบกลับเป็น `text/plain` เสมอ (`[Produces("text/plain")]`) ไม่ว่า header `Accept` จะเป็นอะไร — body ที่ได้จะเป็น URI แบบ `openid4vp://` ตรงๆ หรือ error-code string เปล่าๆ ไม่ได้ห่อด้วย JSON

### การยืนยันตัวตน (Authentication)

| รูปแบบ | ใช้กับ | หมายเหตุ |
|---|---|---|
| ไม่ต้องยืนยันตัวตน (public) | endpoint โปรโตคอลทั้งหมดใน `/openid4vc/*`, `POST /verifier/scan` | ถูกเรียกโดย Wallet หรือเครื่องสแกน QR โดยตรง — ไม่ต้อง login |
| Cookie (ผ่าน ThaID) | `/verifier/status/{id}`, `/VerifyScanQR`, `/PresentResult/VerifyResult`, `/AuditLog`, `POST /Account/Logout` | ใช้ ASP.NET Cookie authentication (`CookieAuthenticationDefaults`) ออก cookie ผ่าน `/Account/ThaIDSignIn` หลังจาก round trip กับ ThaID เสร็จ จุดเริ่ม login: `/Account/ThaIDLogin` คำขอที่ไม่ได้ login ภายใต้ `/verifier/*` จะได้ `401` ตรงๆ ส่วนเส้นทางอื่นจะถูก redirect (`302`) ไปหน้า login |
| ไม่ต้องยืนยันตัวตน (ป้องกันด้วยรหัสที่เดาไม่ได้แทน) | `GET /PresentResult/Result/{responseCode}` | ตั้งใจให้เป็น `[AllowAnonymous]` เพราะเป็นหน้าที่ browser ของ Wallet ฝั่ง Holder จะถูก redirect มาทันทีหลัง present เสร็จ จึงบังคับให้ operator login ด้วย ThaID ไม่ได้ ป้องกันด้วย `response_code` แบบสุ่ม 256-bit ที่สร้างใหม่ทุกครั้งและมีอายุใช้งานได้ 30 นาที แทน |

### รูปแบบ error response ทั่วไป

response ที่ล้มเหลวจาก endpoint โปรโตคอล `/openid4vc/*` โดยทั่วไปจะมีรูปแบบดังนี้:

```json
{
  "error": "invalid_request <บริบทสั้นๆ>",
  "error_description": "Present VP is invalid",
  "reason": "<รหัส error ที่ machine อ่านได้ เช่น disclosure_digest_mismatch>"
}
```

`reason` จะปรากฏใน failure path ส่วนใหญ่ (ไม่ใช่ทั้งหมด) — ดูค่าที่เป็นไปได้ของแต่ละ endpoint ด้านล่าง

---

## 1. Endpoint โปรโตคอล OpenID4VP

Controller: `VerifierController` — route prefix `openid4vc` เป็น endpoint โปรโตคอล OpenID4VP ตัวจริงที่ Wallet คุยด้วยโดยตรงผ่าน `request/{id}` และ `verify/{id}`

### 1.1 `POST /generate-vp-qr`

สร้าง session การยืนยันตัวตนใหม่ และคืนค่า Authorization Request URI แบบอ้างอิง (`client_id` + `request_uri`) ที่เอาไปเข้ารหัสเป็น QR ได้

**Auth:** ไม่ต้องยืนยันตัวตน
**Request body** (JSON):

```json
{
  "document_type": "Transcript"
}
```

`document_type` เป็นได้หนึ่งใน: `Transcript`, `IDCard`, `DriverLicense`, `Bootcamp`

**Response — `200 OK`:**

```json
{
  "authorization_request_uri": "openid4vp://authorize?client_id=...&request_uri=...",
  "deeplink_uri": "walletapp://callback?client_id=...&request_uri=...",
  "qr_text": "openid4vp://authorize?client_id=...&request_uri=...",
  "qr_image_base64": "<base64 PNG ไม่มี prefix data:>",
  "state": "<session id, GUID>",
  "nonce": "<base64url 43 ตัวอักษร, สุ่ม 256-bit>"
}
```

`qr_text` / `authorization_request_uri` ใช้ render เป็น QR code สำหรับสแกนข้ามอุปกรณ์ ส่วน `deeplink_uri` ใช้กับปุ่ม "เปิด wallet" บนอุปกรณ์เดียวกัน

---

### 1.2 `GET /openid4vc/request/{id}`

Request URI endpoint — จุดที่ Wallet เรียก dereference หลังจากได้รับ `client_id` + `request_uri` จากขั้นตอน 1.1 คืนค่าเป็น Request Object ของ OpenID4VP ที่เซ็นแล้ว (ES256/P-256, `client_id` prefix `decentralized_identifier:did:key:...` ตาม §5.9.3)

**Auth:** ไม่ต้องยืนยันตัวตน
**Path parameter:** `id` — session id ที่ได้จาก `state` ของ `/generate-vp-qr`

**Response — `200 OK`**, `Content-Type: application/oauth-authz-req+jwt`, body เป็น compact JWS ดิบๆ (ไม่ใช่ JSON):

```
eyJhbGciOiJFUzI1NiIsInR5cCI6Im9hdXRoLWF1dGh6LXJlcSt...
```

รูปแบบ payload หลัง decode:

```json
{
  "response_type": "vp_token",
  "client_id": "decentralized_identifier:did:key:zDna...",
  "response_mode": "direct_post",
  "state": "<session id>",
  "dcql_query": { "credentials": [ { "id": "...", "format": "...", "meta": {...}, "claims": [...] } ] },
  "client_metadata": { "vp_formats_supported": { "...": {...} } },
  "nonce": "<nonce ของ session>",
  "response_uri": "https://.../openid4vc/verify/<session id>"
}
```

**Response — `404 Not Found`:** document type ไม่ตรงกับ session, หรือ session ไม่มีอยู่ / หมดอายุแล้ว (`ExpiresAt < now`)

---

### 1.3 `POST /openid4vc/verify/{id}`

`response_uri` ที่ Request Object ที่เซ็นแล้วชี้มา — จุดที่ Authorization Response แบบ `direct_post` ของ Wallet ส่งมาถึง

**Auth:** ไม่ต้องยืนยันตัวตน
**Path parameter:** `id` — session id (ต้องตรงกับ form field `state`)
**Request body** (`application/x-www-form-urlencoded`):

| Field | จำเป็นหรือไม่ | หมายเหตุ |
|---|---|---|
| `state` | ต้องมี | ต้องตรงกับ session id ใน path |
| `vp_token` | มีเงื่อนไข | ต้องมีเว้นแต่มี `error` มาแทน รูปแบบล่าสุดคือ JSON object (`{"<dcql id>": ["<jws-or-sd-jwt>"]}`) ส่วนรูปแบบเดิมที่เป็น JSON array เปล่าๆ ยังรองรับสำหรับ Wallet รุ่นเก่า |
| `error` | ไม่บังคับ | Authorization Error Response จาก Wallet — ใช้แทน `vp_token` ไม่ได้ใช้พร้อมกัน |
| `error_description` | ไม่บังคับ | มีความหมายเมื่อมี `error` มาด้วยเท่านั้น |
| `error_uri` | ไม่บังคับ | รับไว้แต่ยังไม่ได้ใช้งานต่อ |
| `device_engagement` | เฉพาะ mso_mdoc | CBOR แบบ base64url — จำเป็นเมื่อ document type ของ session เป็น `mso_mdoc` (proximity flow ผ่าน NFC) |
| `e_reader_key` | เฉพาะ mso_mdoc | CBOR แบบ base64url เงื่อนไขเดียวกับข้างต้น |
| `handover_select` | เฉพาะ mso_mdoc | CBOR แบบ base64url เงื่อนไขเดียวกับข้างต้น |
| `handover_request` | เฉพาะ mso_mdoc | CBOR แบบ base64url ไม่บังคับแม้เป็น mso_mdoc |

**Response — `200 OK`:**

```json
{ "redirect_uri": "https://.../PresentResult/Result/<response_code>" }
```

`response_code` เป็นค่าสุ่ม 256-bit ใหม่ที่สร้างขึ้นทุกครั้งที่ตอบกลับสำเร็จ — ไม่ใช่ session id

**Response — `400 Bad Request`:** ดูรูปแบบ error ทั่วไปด้านบน ค่า `reason` ที่อาจพบ:

| `reason` | ความหมาย |
|---|---|
| `vp_signature_invalid` | ลายเซ็น JWS ของ VP/issuer ชั้นนอกไม่ผ่านการตรวจสอบ (key ผิด, alg ผิด, resolve DID ไม่สำเร็จ) |
| `disclosure_digest_mismatch` | digest ของ claim ที่ disclose มาไม่ตรงกับ `_sd` ที่เซ็นไว้ในเครดิต |
| `missing_kb_jwt` / `invalid_kb_jwt_signature` | ไม่มี Key Binding JWT ของ SD-JWT หรือลายเซ็นไม่ผ่าน |
| `sd_hash_mismatch` | `sd_hash` ใน KB-JWT ไม่ตรงกับ issuer-JWT + ชุด disclosure ที่ส่งมา |
| `nonce_mismatch` / `audience_mismatch` | `nonce`/`aud` (ของ VP-JWT หรือ KB-JWT) ไม่ตรงกับ session นี้ |
| `credential_expired` / `credential_not_yet_valid` | `nbf`/`exp` ของเครดิตเองไม่ผ่านช่วงเวลาที่ใช้งานได้ |
| `unexpected_credential_format` / `unexpected_credential_type` | เครดิตที่ส่งมาไม่ตรงกับ DCQL query ที่ session นี้เก็บไว้ |
| `malformed_engagement_bytes` / `missing_engagement_bytes` | field proximity ของ mso_mdoc หายไปหรือ decode ไม่ได้ |
| (error code ของ Wallet เอง เช่น `access_denied`) | Wallet ปฏิเสธ/ล้มเหลว — ส่งผ่านมาตรงๆ |

ทุก failure path จะทำให้ session ถูก mark เป็น `Failed` (ตรวจสอบได้ผ่าน `GET /verifier/status/{id}`, §2.2) session หนึ่งจะตอบกลับได้ครั้งเดียวเท่านั้น — การส่ง response ซ้ำเข้ามาที่ session ที่เป็น `Consumed` หรือ `Failed` แล้ว (หรือหมดอายุแล้ว) จะถูกปฏิเสธด้วย `error: "invalid_request reject" / "invalid_request expire"` ก่อนที่จะเริ่มกระบวนการตรวจสอบทาง cryptographic ใดๆ

---

### 1.4 `GET /openid4vc/vp/{id}` — **ปิดใช้งานแล้ว**

**Response — `410 Gone`:**

```json
{
  "error": "endpoint_disabled",
  "error_description": "This endpoint has been disabled pending authorization controls (see H-08 in the compliance audit)."
}
```

เดิมทีคืนค่า VP/VC token ที่เก็บไว้ดิบๆ สำหรับ session id ใดก็ได้โดยไม่มีการตรวจสอบสิทธิ์เลย ปัจจุบันเหลือไว้ในโค้ดเป็นเพียง stub ที่คืนค่า `410` เสมอ

---

## 2. Endpoint สำหรับสแกน QR / Broker

Controller: `VerifierScanController` — route prefix `verifier` ใช้โดยเครื่องสแกนของ operator (เครื่องอ่าน QR/laser) ที่ส่งต่อโค้ดที่สแกนได้ไปยัง broker service ซึ่งจะไปขับเคลื่อน Wallet ต่ออีกที

### 2.1 `POST /verifier/scan`

**Auth:** Cookie (`[Authorize]` ที่ controller) — ถูกเรียกจาก browser session ที่ login แล้วของ operator เอง (JavaScript ใน `VerifyScanQR.cshtml`) ไม่ใช่ Wallet เรียกโดยตรง
**Produces:** `text/plain` (เสมอ — ดูหัวข้อภาพรวม)
**Request body** (JSON):

```json
{
  "scanned_value": "https://broker.example/broker/session/<id>/request",
  "doc_type": "DriverLicense"
}
```

**Response ที่เป็นไปได้:**

| Status | Body | ความหมาย |
|---|---|---|
| `200` | `openid4vp://authorize?client_id=...&request_uri=...` | broker รับคำขอที่ส่งต่อมาแล้ว ให้นำ URI นี้ไปให้ Wallet ต่อ |
| `400` | `empty_scanned_value` | ไม่มี `scanned_value` ใน request body |
| `400` | `doc_type_required` | ไม่มี `doc_type` ใน request body |
| `400` | `invalid_qr_content` | ค่าที่สแกนได้ไม่ใช่ URI แบบ absolute หรือดึง session id จาก path ไม่ได้ (รูปแบบที่คาดหวัง `.../session/{sessionId}/...`) |
| `400` | `unknown_doc_type` | `doc_type` ไม่ตรงกับ document type ที่ตั้งค่าไว้ |
| `403` | `untrusted_broker_endpoint` | URL ที่สแกนได้ไม่ผ่าน allowlist ของ broker — host ไม่อยู่ใน `AllowedBrokerHosts` หรือ port ไม่อยู่ใน `AllowedBrokerPorts` (`appsettings.json`) |
| `502` | `broker_unreachable` | เกิด network error ตอนเรียก broker |
| `500` | อื่นๆ | broker ตอบกลับด้วยสถานะที่ไม่สำเร็จ หรือ error ที่ยังไม่ได้จัดหมวดหมู่ |

---

### 2.2 `GET /verifier/status/{sessionId}`

endpoint สำหรับ poll จาก UI ของ operator เพื่อเช็คว่า Wallet ตอบกลับมาแล้วหรือยัง

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

`status` สะท้อนคอลัมน์ `Status` ของ session แถวนั้นเอง (`Pending` / `Consumed` / `Failed`) รวมกับการหมดอายุ — ไม่ได้ดูแค่ "มีแถว response หรือไม่" เหมือนเดิม ทำให้การยืนยันตัวตนที่ล้มเหลวถูกรายงานเป็น `failed` ทันที แทนที่จะค้างเป็น `pending` จนกว่า session จะหมดอายุ (แก้ไขตามข้อค้นพบ M-04 ใน compliance audit) `claims` (จะมีเฉพาะตอน `completed`) เป็นการ decode claim ที่ disclose มาจาก VC payload ที่เก็บไว้แบบ best-effort เพื่อการแสดงผลเท่านั้น ไม่ได้ตรวจสอบซ้ำ ณ จุดนี้

---

## 3. หน้าแสดงผลลัพธ์และหน้าสำหรับ Operator

Controller: `PresentResultController` เป็นหน้า HTML ที่ render ฝั่ง server (Razor view) ไม่ใช่ JSON — ใส่ไว้ในเอกสารนี้เพราะยังเป็นส่วนหนึ่งของ HTTP surface ที่เรียกถึงได้

### 3.1 `GET /PresentResult/Result/{responseCode}`

**Auth:** ไม่ต้องยืนยันตัวตน (`[AllowAnonymous]` — ดูเหตุผลในหัวข้อภาพรวม)
หน้าที่ browser ของ Wallet ฝั่ง Holder จะถูก redirect มาหลังจาก §1.3 สำเร็จ ค้นหาผลลัพธ์ด้วย `response_code` (ไม่ใช่ session id) ใช้งานได้ 30 นาทีนับจาก `ReceivedAt` แสดงผล claim ของ VP/VC ที่ decode แล้ว หากรหัสไม่รู้จักหรือหมดอายุแล้วจะแสดงหน้า "ไม่พบข้อมูล" (ยังคืนค่า `200`)

### 3.2 `GET /PresentResult/VerifyResult`

**Auth:** Cookie (`[Authorize]`)
หน้าแลนดิ้งสำหรับ operator/user ที่ login ด้วย ThaID แล้ว (คนละหน้ากับหน้าที่ Wallet เข้าด้านบน)

### 3.3 `GET /VerifyScanQR`

**Auth:** Cookie (`[Authorize]`)
UI เครื่องสแกน QR ของ operator — ขับเคลื่อน §2.1/§2.2 ผ่าน JavaScript (`fetch`) รวมถึงมี listener สำหรับเครื่องสแกนแบบ keyboard-wedge HID ด้วย

---

## 4. การยืนยันตัวตน (Authentication)

Controller: `AccountController` มีกลไก login คู่ขนานสองแบบ: แบบ username/password รูปแบบเดิม และ ThaID (แบบที่ใช้งานจริงในการปฏิบัติงาน)

### 4.1 `GET /Account/Login`

**Auth:** ไม่ต้องยืนยันตัวตน — render ฟอร์ม login Query: `ReturnUrl` (ไม่บังคับ)

### 4.2 `POST /Account/Login`

**Auth:** ไม่ต้องยืนยันตัวตน, `[ValidateAntiForgeryToken]`
**Body:** form field `username`, `password`, `ReturnUrl` (ไม่บังคับ)
สำเร็จ: ออก auth cookie และ redirect ไปที่ `ReturnUrl` (ถ้าเป็น URL ภายใน) หรือ `PresentResult/VerifyResult` ล้มเหลว: render ฟอร์มเดิมพร้อม error การตรวจสอบ

### 4.3 `POST /Account/Logout`

**Auth:** Cookie (`[Authorize]`) — sign out cookie แล้ว redirect ไปหน้า `Login`

### 4.4 `GET /Account/AccessDenied`

**Auth:** ไม่ต้องยืนยันตัวตน — หน้า "access denied" แบบ static ใช้เป็น `AccessDeniedPath` ของ Cookie auth scheme

### 4.5 `GET /Account/ThaIDSignIn`

**Auth:** ไม่ต้องยืนยันตัวตน — เป็นปลายทางที่ gateway ของ ThaID callback กลับมา
**Query:** `pid` (จำเป็น — เลขบัตรประชาชนที่ยืนยันแล้วจาก ThaID), `ReturnUrl` (ไม่บังคับ)
ออก auth cookie จาก `pid` โดยตรง (ThaID ยืนยันตัวตนมาแล้ว) จากนั้น redirect — โดยเลือก `ReturnUrl` ก่อน ถ้าไม่มีจะใช้ `ReturnUrl` ที่เก็บไว้ใน cookie `thaiid_pending_return` ก่อนหน้า (ดู 4.7) สุดท้ายถ้าไม่มีทั้งคู่จะไปที่ `PresentResult/VerifyResult`

### 4.6 `GET /Account/ThaIDLogin`

**Auth:** ไม่ต้องยืนยันตัวตน — render view โดยใส่ `ReturnUrl`/`documentType` ไว้ใน `ViewBag` สำหรับ hidden form field Query: `ReturnUrl`, `documentType` (ไม่บังคับทั้งคู่)

### 4.7 `GET /thaiid/login`

**Auth:** ไม่ต้องยืนยันตัวตน — เป็น action ที่ "เริ่ม login ผ่าน ThaID" จริงๆ (สังเกตว่า route เป็นตัวพิมพ์เล็กแยกจาก action ในข้อ 4.6 ที่ชื่อคล้ายกัน)
**Query:** `returnUrl`, `documentType`, `error` (ไม่บังคับทั้งหมด)
เก็บ `{returnUrl, documentType}` ไว้ใน cookie อายุสั้น (`thaiid_pending_return`, `HttpOnly`+`Secure`, อายุ 10 นาที — จำเป็นเพราะ callback ของ ThaID gateway เองไม่ได้ส่ง parameter ที่กำหนดเองกลับมาด้วย) จากนั้น `302` ไปที่ ThaID gateway (`ThaIDConfig.GatewayBaseUrl`) พร้อม `clientid`, `role=verifier`, `documentType`

---

## 5. Audit Log

Controller: `AuditLogController`

### 5.1 `GET /AuditLog`

**Auth:** Cookie (`[Authorize]`)
**Query:** `page` (ค่าเริ่มต้น `1`), `status` (ไม่บังคับ — `success` หรือ `failed` ค่าอื่นจะถูกละเว้นไม่ใช้กรอง)
view ที่ render ฝั่ง server แบบแบ่งหน้า (50 รายการ/หน้า) จากตาราง `dbverifierlog` — จะมีการเขียนหนึ่งแถวทุกครั้งที่เรียก `POST /openid4vc/verify/{id}` (ผ่าน `VerifierAuditLogFilter`) ทั้งกรณีสำเร็จและล้มเหลว รวมถึง error reason, IP ผู้ร้องขอ, และ User-Agent ไม่เปิดให้เข้าถึงแบบสาธารณะ เพราะแสดงข้อมูลเชิงปฏิบัติการที่เกี่ยวข้องกับตัวตน

---

## ภาคผนวก A — วงจรสถานะของ Session

ทุก session (`Dbverifiersession`) ที่สร้างโดย `POST /generate-vp-qr` จะเปลี่ยนสถานะดังนี้:

```
Pending ──(Wallet ตอบกลับ, ตรวจสอบผ่าน)──▶ Consumed
   │
   ├──(Wallet ตอบกลับ, ตรวจสอบไม่ผ่านไม่ว่าเหตุผลใด)──▶ Failed
   │
   └──(ครบกำหนด ExpiresAt โดยไม่มีการตอบกลับ)──▶ (ยังคงเป็น Pending; §2.2 จะรายงานเป็น "expired")
```

session หนึ่งจะออกจากสถานะ `Pending` ได้เพียงครั้งเดียว — ทั้ง `Consumed` และ `Failed` จะปฏิเสธการเรียก `POST /openid4vc/verify/{id}` ซ้ำสำหรับ session id เดิม (ป้องกัน replay)

## ภาคผนวก B — รูปแบบ `vp_token` ใน response (OpenID4VP §8.1 ฉบับ final)

```json
{
  "<id ของ credential query ใน dcql>": ["<jws-หรือ-sd-jwt-presentation>"]
}
```

แต่ละ key คือ `id` ของ Credential Query จาก `dcql_query` ที่ session นั้นเก็บไว้ ส่วน value เป็น array ของ Presentation ที่ตรงกันหนึ่งรายการขึ้นไป รูปแบบเดิมที่เป็น array เปล่าๆ (`["<jws>"]`) ยังรองรับสำหรับ Wallet รุ่นเก่า

## ภาคผนวก C — ตัวอย่าง DCQL query (ที่ส่งมาใน Request Object ของ §1.2)

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

## ภาคผนวก D — ข้อควรทราบสำหรับผู้ใช้ API

- ให้ถือว่า `nonce` และ `state` ที่ได้จาก §1.1 เป็นค่าใช้ครั้งเดียวและผูกกับ session นั้นๆ — นำไปใช้ซ้ำข้าม session ไม่ได้
- `response_code` (จาก `redirect_uri` ของ §1.3) เป็นสิ่งเดียวที่ใช้ป้องกันการเข้าถึงหน้าผลลัพธ์ (§3.1) ไม่ใช่ session id และตั้งใจให้เดาไม่ได้ — อย่าพยายามคำนวณหรือเดารหัสนี้
- endpoint ใน `/openid4vc/*` ไม่มีการจำกัด rate limit หรือ CORS นอกเหนือจาก policy ของ `AllowedBrokerHosts`/CORS ที่ตั้งค่าไว้ใน `Program.cs` เนื่องจากออกแบบมาให้ Wallet เรียกผ่านอินเทอร์เน็ตสาธารณะได้ ตามโมเดลโปรโตคอลของ OpenID4VP
- `GET /openid4vc/request/{id}` และ `POST /openid4vc/verify/{id}` ใช้ได้ครั้งเดียวต่อ session — อย่า poll หรือ retry ซ้ำกับ session id เดิม โดยคาดหวังผลลัพธ์ที่ต่างไปหลังจาก session เข้าสู่สถานะสุดท้ายแล้ว (`Consumed`/`Failed`)

## ภาคผนวก E — รายการที่ยังไม่ปิด (ไม่ใช่ส่วนหนึ่งของ API แต่ใส่ไว้เพื่อความครบถ้วน)

- **C-05 (ยังไม่ปิด):** `appsettings.json` ยังเก็บ `ClientSecret` ของ ThaID เป็น plaintext อยู่ ยังไม่ได้ rotate/ย้ายออกไปเป็น environment variable — พบใน `OID4VP-1.0-COMPLIANCE-AUDIT.md` ยังไม่มีการดำเนินการจนกว่าจะได้รับการยืนยัน
- **`direct_post.jwt` (ยังไม่ implement):** ปัจจุบันรองรับเฉพาะ `direct_post` แบบธรรมดาเป็น response mode เท่านั้น หากต้องการ response แบบเข้ารหัส จะต้องเพิ่ม encryption keypair ฝั่ง Verifier และเพิ่มการ decrypt JWE ใน §1.3
