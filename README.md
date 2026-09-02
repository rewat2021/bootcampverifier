# คู่มือ Deploy VerifierAPI ผ่าน Docker (Environment / Secrets)

**อัปเดตล่าสุด:** 2026-08-26

## ภาพรวม

ตั้งแต่การแก้ไขรอบนี้ **secret ทั้งหมดของ VerifierAPI มาจากไฟล์ `.env` ไฟล์เดียวที่ root ของ repo** 

`docker-compose.yml` มี `env_file: .env` — inject ตัวแปรเข้า container โดยตรงตอน `docker-compose up`

## 1. ตัวแปรใน `.env`

| ตัวแปร                      | จำเป็นหรือไม่                          | คำอธิบาย                                                                                                                                                                                                                               |
| --------------------------- | -------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `CONNECTION_STRING`         | จำเป็น                                 | connection string เชื่อม MySQL รูปแบบ `server=<host>;port=<port>;database=<db>;user=<user>;password=<password>` ปัจจุบันชี้ไปที่ MySQL remote server (ไม่ใช่ container ในเครื่อง)                                                      |
| `MYSQL_ROOT_PASSWORD`       | ไม่ใช้แล้ว                             | เดิมใช้เฉพาะตอนที่ `docker-compose.yml` ยังมี service `verifier-mysql` (MySQL local ในเครื่อง) — ตอนนี้เอา service นั้นออกแล้วเพราะ deploy ลง remote server จริง ไม่ต้องตั้งค่านี้อีก (จะเก็บบรรทัดนี้ไว้เฉยๆ ใน `.env` ก็ไม่มีผลอะไร) |
| `ThaIDConfig__ClientID`     | จำเป็น                                 | client id ที่ได้จาก ThaID gateway                                                                                                                                                                                                      |
| `ThaIDConfig__ClientSecret` | จำเป็น                                 | client secret จาก ThaID gateway                                                                                                                                                                                                        |
| `ASPNETCORE_ENVIRONMENT`    | จำเป็น                                 | `Production` หรือ `Development`                                                                                                                                                                                                        |
| `BASE_URL`                  | จำเป็น                                 | URL สาธารณะของ VerifierAPI เอง ที่ browser/Wallet ภายนอกเข้าถึงได้                                                                                                                                                                     |
| `INTERNAL_BASE_URL`         | จำเป็น                                 | URL ของ VerifierAPI เอง ที่ใช้สร้าง `response_uri`/callback ภายในโปรโตคอล OpenID4VP (คนละความหมายกับ `ISSUER_BASE_URL` — อย่าใช้ปนกัน)                                                                                                 |
| `ISSUER_BASE_URL`           | จำเป็นถ้าใช้ `dc+sd-jwt`/`jwt_vc_json` | URL ของ Issuer ใช้สร้างค่า `vct_values`/`type_values` ใน DCQL query — priority สูงสุดในโค้ด ต้องตั้งชื่อ key ให้ตรงเป๊ะ (ไม่ใช่ `IssuerUrl`) ไม่งั้นจะถูก `INTERNAL_BASE_URL` บังก่อน                                                  |

## 2. ติดตั้งและรันผ่าน Docker

### 2.1 Prerequisites

- ติดตั้ง Docker + Docker Compose แล้ว
- เครื่องที่รัน Docker เข้าถึง MySQL remote ได้จริง (ทดสอบ `telnet <DB_HOST> 3306` หรือใช้ MySQL client ต่อดูก่อน — `<DB_HOST>` คือ host ของ MySQL server ปลายทางที่ระบุไว้ใน `CONNECTION_STRING` ของ `.env`)

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

### 2.8 หมายเหตุ: `docker-compose.yml` มี service เดียว (`verifier-api`)

ตอนนี้ `docker-compose up` จะสร้าง container `verifier-api` ตัวเดียวเท่านั้น

## 3. Restore ฐานข้อมูลลง MySQL server 

**เป้าหมายของการ restore คือ MySQL server ของระบบปลายทางที่ไปติดตั้งจริง (ตัวเดียวกับที่ระบุใน `CONNECTION_STRING` ของ `.env`) ไม่ใช่ MySQL ในคอนเทนเนอร์ใดๆ** (`docker-compose.yml` ไม่มี MySQL container ) คำสั่งด้านล่างที่ขึ้นต้นด้วย `docker run` คือการยืม **image `mysql:8.0` มาใช้เป็นแค่ตัว client เครื่องมือ** (เหมือนติดตั้งโปรแกรม `mysql`/`mysqldump` ชั่วคราว) เพื่อยิงคำสั่งออกไปหา server ที่ `-h <DB_HOST>` เท่านั้น ตัว container จะถูกลบทิ้งทันทีหลังรันเสร็จ (`--rm`) ไม่มีการเก็บข้อมูลไว้ในคอนเทนเนอร์เลย

แทน `<DB_HOST>` ทุกจุดด้านล่างด้วย host จริงของ MySQL server ปลายทางที่กำลังติดตั้งอยู่ (ดูค่าได้จาก `CONNECTION_STRING` ใน `.env` ของ server นั้นๆ — คนละค่ากันในแต่ละสภาพแวดล้อม เช่น dev/staging/production ไม่ใช่ค่าคงที่ค่าเดียว)

ถ้าเครื่องที่ใช้รันคำสั่งมี `mysql`/`mysqldump` client ติดตั้งอยู่แล้ว จะไม่ใช้ Docker เลยก็ได้ — แค่ตัดคำว่า `docker run --rm mysql:8.0` ออกจากหน้าคำสั่งแต่ละอันด้านล่าง แล้วรัน `mysqldump`/`mysql` ตรงๆ ผลลัพธ์เหมือนกันทุกประการ เพราะเป้าหมายปลายทาง (`-h <DB_HOST>`) เป็นตัวเดียวกัน

ใช้เมื่อมีไฟล์ mysqldump ( `Dump20260826.sql`) ที่ต้องการ import กลับเข้า MySQL server 


### ขั้นตอนที่ 1 — Backup ข้อมูลบน server ปัจจุบันก่อน (กันพลาด)

```bash
docker run --rm mysql:8.0 mysqldump -h <DB_HOST> -P 3306 -u root -p"<password จาก .env>" verifier > backup_before_restore_$(date +%Y%m%d_%H%M%S).sql
```

แทน `<password จาก .env>` ด้วยค่าจริงจาก `CONNECTION_STRING` (ระวังเรื่อง shell history เก็บ password ไว้ — ถ้ากังวลให้ใช้ตัวแปร env ชั่วคราวแทนการพิมพ์ตรงๆ) เก็บไฟล์ backup ที่ได้ไว้นอก repo เช่นเดียวกับไฟล์ dump — ไฟล์นี้คือสำเนาของข้อมูลที่อยู่บน server จริง ไม่ใช่ข้อมูลจากคอนเทนเนอร์ใดๆ

### ขั้นตอนที่ 2 — Restore ไฟล์ dump ลง server

```bash
docker run -i --rm mysql:8.0 mysql -h <DB_HOST> -P 3306 -u root -p"<password จาก .env>" verifier < Dump20260826.sql
```

`-i` จำเป็น (เปิด stdin ให้ container รับไฟล์ dump ที่ redirect เข้ามาจากฝั่ง host ได้) คำสั่งนี้เขียนข้อมูลลงตาราง `verifier` **บน server ปลายทางโดยตรง** — container ที่ใช้รันคำสั่งเป็นเพียงตัวส่งคำสั่งเท่านั้น ไม่ได้เก็บอะไรไว้ที่ตัวเอง

### ขั้นตอนที่ 3 — ตรวจสอบว่าข้อมูลบน server อัปเดตแล้วจริง

```bash
docker run --rm mysql:8.0 mysql -h <DB_HOST> -P 3306 -u root -p"<password จาก .env>" verifier -e "SELECT COUNT(*) FROM dbverifiersession; SELECT COUNT(*) FROM dbdocumenttype;"
```

หรือเปิดแอป (`http://localhost:5001`) แล้วดูหน้า `/AuditLog` หรือลอง flow verify จริงว่าข้อมูลขึ้นถูกต้อง — เพราะแอปต่อ `CONNECTION_STRING` เดียวกันไปที่ server ตัวเดียวกันนี้อยู่แล้ว ถ้า restore สำเร็จ แอปจะเห็นข้อมูลใหม่ทันทีโดยไม่ต้อง restart

### หมายเหตุ

- ไม่ต้อง restart container `verifier-api` หลัง restore DB — แอปต่อ MySQL remote สดทุกครั้งอยู่แล้ว ไม่มีการแคชข้อมูลไว้ในโปรเซส
- ถ้า restore แล้วแอป error เกี่ยวกับ schema ไม่ตรง (เช่น คอลัมน์หาย/ชื่อไม่ตรง) ให้เทียบ schema ในไฟล์ dump กับ `db/init.sql` และ `db/migrations/` ในโปรเจกต์ว่าตรงเวอร์ชันกันหรือไม่ ก่อน restore
- ทั้ง 3 คำสั่งข้างต้นไม่เกี่ยวกับ `docker-compose.yml`/`lab-network` เลย — เป็นแค่ `docker run` ตัวเดี่ยวๆ ที่ยิงตรงไปหา MySQL **server จริง** จากเครื่อง host เท่านั้น ใช้ได้แม้ยังไม่เคย `docker-compose up` มาก่อน

## 4. Rotate ThaID ClientSecret

ตรวจสอบค่า `ClientSecret`, ClientID ในไฟล์ .env


## 5. Troubleshooting

**"CONNECTION_STRING environment variable must be set"** — `.env` หาไม่เจอ หรือ container ไม่ได้ inject env var เข้าไป ตรวจว่า `docker-compose.yml` มี `env_file: .env` และไฟล์ `.env` อยู่ที่เดียวกับ `docker-compose.yml` จริง

**เชื่อม MySQL ไม่ได้ / host resolve ไม่ออก** — เช็คว่า `CONNECTION_STRING` ชี้ไป host จริงที่เข้าถึงได้จากเครื่องที่รัน container `verifier-api` อยู่ (`docker-compose.yml` ไม่มี MySQL container ให้สับสนแล้ว ต้องเป็น host/IP ของ MySQL server ปลายทางเท่านั้น)

**DCQL `vct_values`/`type_values` ชี้ผิดที่ (ไปที่ Verifier เองแทน Issuer)** — ตรวจว่าตั้งชื่อ key เป็น `ISSUER_BASE_URL` ไม่ใช่ `IssuerUrl` (ดูหัวข้อ 1)

**ThaID login ใช้ไม่ได้หลัง rotate secret** — เช็คว่า restart ด้วยวิธีที่ถูกต้องแล้ว (หัวข้อ 2.6) และ secret ใหม่ยัง active อยู่ฝั่ง ThaID gateway จริง
