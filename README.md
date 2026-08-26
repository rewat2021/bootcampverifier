# คู่มือ Deploy VerifierAPI ผ่าน Docker (Environment / Secrets)

**อัปเดตล่าสุด:** 2026-08-26

## 1. ตัวแปรใน `.env`

| ตัวแปร | จำเป็นหรือไม่ | คำอธิบาย |
|---|---|---|
| `CONNECTION_STRING` | จำเป็น | connection string เชื่อม MySQL รูปแบบ `server=<host>;port=<port>;database=<db>;user=<user>;password=<password>` ปัจจุบันชี้ไปที่ MySQL remote server (ไม่ใช่ container ในเครื่อง) |
| `MYSQL_ROOT_PASSWORD` | ใช้เฉพาะกรณีรัน container `verifier-mysql` เองในเครื่อง | ไม่เกี่ยวถ้าต่อ MySQL remote อย่างเดียวตามที่ตั้งค่าไว้ตอนนี้ |
| `ThaIDConfig__ClientID` | จำเป็น | client id ที่ได้จาก ThaID gateway — bind เข้า `ThaIDConfig:ClientID` ผ่าน naming convention แบบ double-underscore ของ .NET |
| `ThaIDConfig__ClientSecret` | จำเป็น | client secret จาก ThaID gateway — **ต้อง rotate เป็นค่าใหม่** เพราะค่าเดิมเคย commit ขึ้น git มาก่อน ถือว่ารั่วแล้ว (ดูหัวข้อ 4) |
| `ASPNETCORE_ENVIRONMENT` | จำเป็น | `Production` หรือ `Development` |
| `BASE_URL` | จำเป็น | URL สาธารณะของ VerifierAPI เอง ที่ browser/Wallet ภายนอกเข้าถึงได้ |
| `INTERNAL_BASE_URL` | จำเป็น | URL ของ VerifierAPI เอง ที่ใช้สร้าง `response_uri`/callback ภายในโปรโตคอล OpenID4VP (คนละความหมายกับ `ISSUER_BASE_URL` — อย่าใช้ปนกัน) |
| `ISSUER_BASE_URL` | จำเป็นถ้าใช้ `dc+sd-jwt`/`jwt_vc_json` | URL ของ Issuer ใช้สร้างค่า `vct_values`/`type_values` ใน DCQL query — priority สูงสุดในโค้ด ต้องตั้งชื่อ key ให้ตรงเป๊ะ (ไม่ใช่ `IssuerUrl`) ไม่งั้นจะถูก `INTERNAL_BASE_URL` บังก่อน |

## 2. ติดตั้งและรันผ่าน Docker

### 2.1 Prerequisites

- ติดตั้ง Docker + Docker Compose แล้ว
- เครื่องที่รัน Docker เข้าถึง MySQL remote ได้จริง (ทดสอบ `telnet 192.100.10.48 3306` หรือใช้ MySQL client ต่อดูก่อน)

### 2.2 สร้าง Docker network ภายนอกที่จำเป็น

`docker-compose.yml` ประกาศ network แบบ `external: true`:

```yaml
networks:
  lab-network:
    external: true
```

หมายความว่า network นี้ต้องมีอยู่ก่อนแล้วเท่านั้น — compose **จะไม่สร้างให้เอง** ถ้ายังไม่เคยสร้าง ให้รันครั้งเดียว (ครั้งต่อไปไม่ต้องรันซ้ำ):

```bash
docker network create lab-network
```

### 2.3 ตั้งค่า `.env`

ตรวจว่า `bootcamp_verifier/.env` มีค่าจริงครบตามหัวข้อ 1 ด้านบน (ไม่ใช่ placeholder)

### 2.4 Build และ start

```bash
docker-compose up -d --build
```

ใส่ `--build` ทุกครั้งที่เพิ่งแก้โค้ด/`appsettings.json`/`Program.cs` เพื่อบังคับ build image ใหม่แทนที่จะใช้ image เดิมที่แคชไว้

### 2.5 ตรวจสถานะ

```bash
docker-compose ps
docker-compose logs -f verifier-api
```

ทดสอบเปิด Swagger: `http://localhost:5001/swagger`

### 2.6 แก้ `.env` แล้วต้องการให้มีผล

**ห้ามใช้ `docker-compose restart`** (ไม่ reread `.env`) ให้ใช้:

```bash
docker-compose down
docker-compose up -d
```

หรือ

```bash
docker-compose up -d --force-recreate
```

### 2.7 หยุดระบบ

```bash
docker-compose down
```

ข้อมูลใน volume `verifier-mysql-data` จะยังอยู่แม้ `down` แล้ว เว้นแต่สั่ง `docker-compose down -v` (ลบ volume ด้วย — ระวังถ้ามีข้อมูลสำคัญอยู่ในนั้น)

### 2.8 หมายเหตุ: MySQL container ในเครื่องไม่ได้ถูกใช้งานจริง

`docker-compose.yml` ยังนิยาม service `verifier-mysql` ไว้ และ `verifier-api` ตั้ง `depends_on: verifier-mysql: condition: service_healthy` — เพราะตอนนี้ `CONNECTION_STRING` ชี้ไป MySQL remote (`192.100.10.48`) โดยตรงแล้ว container `verifier-mysql` ในเครื่องจะยังถูกสร้างขึ้นมาด้วยทุกครั้งที่ `docker-compose up` แต่**ไม่ได้ถูกใช้งานจริงเลย** — เสียพื้นที่ดิสก์และพอร์ต 3307 ไปโดยเปล่าประโยชน์ ไม่กระทบการทำงาน (แค่เสียทรัพยากรเฉยๆ) แต่ถ้าต้องการตัดออกให้เหลือรันแค่ `verifier-api` อย่างเดียว บอกได้ ผมแก้ `docker-compose.yml` ให้เอา service `verifier-mysql` กับ `depends_on` ออกได้เลย

## 3. Restore ฐานข้อมูลจากไฟล์ dump (.sql)

ใช้เมื่อมีไฟล์ mysqldump (เช่น `Dump20260826.sql`) ที่ต้องการ import กลับเข้า MySQL remote (`192.100.10.48`) — ไฟล์แบบนี้มักได้มาจากการ backup ด้วย `mysqldump` หรือมีคนส่งมาให้ทีม

### คำเตือนก่อนเริ่ม

- ไฟล์ dump ที่มีข้อมูลจริง (session, VP/VC ที่ capture มา, log การ verify ฯลฯ) **ห้ามใส่ไว้ใน repo หรือ commit ขึ้น git เด็ดขาด** — เก็บไว้แยกนอก repo เท่านั้น ตรงตาม `OID4VP-1.0-COMPLIANCE-AUDIT.md` finding C-05 ที่เพิ่งปิดไป (ไฟล์ `Dump20260826.sql` ที่ใช้อ้างอิงในคู่มือนี้มีข้อมูล session/response จริงอยู่ — ยืนยันแล้วว่าไม่ได้ถูกคัดลอกเข้า repo)
- ไฟล์ dump ที่ generate จาก `mysqldump` แบบมาตรฐานจะมี `DROP TABLE IF EXISTS` ก่อนสร้างตารางใหม่ทุกตาราง — แปลว่า restore แล้ว **ข้อมูลเดิมในตารางที่ชื่อตรงกันจะหายไปทั้งหมด** แทนที่ด้วยข้อมูลในไฟล์ dump ควร backup DB ปัจจุบันก่อนเสมอ

รันทุกคำสั่งด้านล่างผ่าน `docker run` ด้วย image `mysql:8.0` — **ไม่ต้องติดตั้ง `mysql` client บนเครื่องเลย** เพราะยืม image เดียวกับที่ใช้ใน `docker-compose.yml` มารันเป็น client ชั่วคราวแทน (`--rm` ลบ container ทิ้งทันทีหลังรันเสร็จ) ให้รันคำสั่งจากโฟลเดอร์ที่มีไฟล์ dump อยู่ (เช่นโฟลเดอร์ที่เก็บ `Dump20260826.sql` ไว้นอก repo)

### ขั้นตอนที่ 1 — Backup DB ปัจจุบันก่อน (กันพลาด)

```bash
docker run --rm mysql:8.0 mysqldump -h 192.100.10.48 -P 3306 -u root -p"<password จาก .env>" verifier > backup_before_restore_$(date +%Y%m%d_%H%M%S).sql
```

แทน `<password จาก .env>` ด้วยค่าจริงจาก `CONNECTION_STRING` (ระวังเรื่อง shell history เก็บ password ไว้ — ถ้ากังวลให้ใช้ตัวแปร env ชั่วคราวแทนการพิมพ์ตรงๆ) เก็บไฟล์ backup ที่ได้ไว้นอก repo เช่นเดียวกับไฟล์ dump

### ขั้นตอนที่ 2 — Restore ไฟล์ dump

```bash
docker run -i --rm mysql:8.0 mysql -h 192.100.10.48 -P 3306 -u root -p"<password จาก .env>" verifier < Dump20260826.sql
```

`-i` จำเป็น (เปิด stdin ให้ container รับไฟล์ dump ที่ redirect เข้ามาจากฝั่ง host ได้) ไม่ต้อง mount volume ใดๆ เพิ่ม

### ขั้นตอนที่ 3 — ตรวจสอบหลัง restore

```bash
docker run --rm mysql:8.0 mysql -h 192.100.10.48 -P 3306 -u root -p"<password จาก .env>" verifier -e "SELECT COUNT(*) FROM dbverifiersession; SELECT COUNT(*) FROM dbdocumenttype;"
```

หรือเปิดแอป (`http://localhost:5001`) แล้วดูหน้า `/AuditLog` หรือลอง flow verify จริงว่าข้อมูลขึ้นถูกต้อง

### หมายเหตุ

- ไม่ต้อง restart container `verifier-api` หลัง restore DB — แอปต่อ MySQL remote สดทุกครั้งอยู่แล้ว ไม่มีการแคชข้อมูลไว้ในโปรเซส
- ถ้า restore แล้วแอป error เกี่ยวกับ schema ไม่ตรง (เช่น คอลัมน์หาย/ชื่อไม่ตรง) ให้เทียบ schema ในไฟล์ dump กับ `db/init.sql` และ `db/migrations/` ในโปรเจกต์ว่าตรงเวอร์ชันกันหรือไม่ ก่อน restore
- ทั้ง 3 คำสั่งข้างต้นไม่เกี่ยวกับ `docker-compose.yml`/`lab-network` เลย — เป็นแค่ `docker run` ตัวเดี่ยวๆ ที่ยิงตรงไปหา MySQL remote จากเครื่อง host เท่านั้น ใช้ได้แม้ยังไม่เคย `docker-compose up` มาก่อน

## 4. Rotate ThaID ClientSecret

ค่า `ClientSecret` เดิมเคยถูก commit ไว้ใน `appsettings.json` มาก่อน (พบระหว่างการตรวจสอบตาม `OID4VP-1.0-COMPLIANCE-AUDIT.md` finding C-05) ต้องถือว่ารั่วแล้วแม้จะลบออกจาก working tree ปัจจุบันไปแล้วก็ตาม เพราะยังอยู่ใน git history

ขั้นตอน:

1. ติดต่อ ThaID gateway admin เพื่อขอ `ClientSecret` ใหม่ และแจ้งให้ revoke ค่าเดิม
2. แก้บรรทัด `ThaIDConfig__ClientSecret=` ใน `.env` เป็นค่าใหม่
3. รีสตาร์ทตามหัวข้อ 2.6 (`docker-compose down` + `up -d`)
4. ทดสอบ flow login ผ่าน ThaID (`/thaiid/login` → `/Account/ThaIDSignIn`) ว่าใช้งานได้ปกติ
5. (แนะนำ ยังไม่ได้ทำ) ลบค่าเดิมออกจาก git history ด้วย `git filter-repo` หรือ BFG Repo-Cleaner — เป็น operation ที่กระทบ history ทั้ง repo ต้องตัดสินใจร่วมกับทีมก่อนทำ

## 5. Troubleshooting

**"CONNECTION_STRING environment variable must be set"** — `.env` หาไม่เจอ หรือ container ไม่ได้ inject env var เข้าไป ตรวจว่า `docker-compose.yml` มี `env_file: .env` และไฟล์ `.env` อยู่ที่เดียวกับ `docker-compose.yml` จริง

**เชื่อม MySQL ไม่ได้ / host resolve ไม่ออก** — เช็คว่า `CONNECTION_STRING` ชี้ไป host ที่เข้าถึงได้จริงจากเครื่องที่รัน container อยู่ (ไม่ใช่ชื่อ Docker service เช่น `verifier-mysql` ถ้าไม่ได้รันในเครือข่าย Docker เดียวกัน)

**DCQL `vct_values`/`type_values` ชี้ผิดที่ (ไปที่ Verifier เองแทน Issuer)** — ตรวจว่าตั้งชื่อ key เป็น `ISSUER_BASE_URL` ไม่ใช่ `IssuerUrl` (ดูหัวข้อ 1)

**ThaID login ใช้ไม่ได้หลัง rotate secret** — เช็คว่า restart ด้วยวิธีที่ถูกต้องแล้ว (หัวข้อ 2.6) และ secret ใหม่ยัง active อยู่ฝั่ง ThaID gateway จริง
