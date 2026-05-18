# Lab Setup Guide

## Requirements

- **Docker Desktop** — [download.docker.com](https://www.docker.com/products/docker-desktop/)  
  (ต้องเปิด Docker Desktop ก่อนรัน script ทุกครั้ง)

---

## วิธีรัน

### macOS / Linux

```bash
tar -xzf lab-*-arm64.tar.gz        # Apple Silicon (M1/M2/M3)
# หรือ
tar -xzf lab-*-amd64.tar.gz        # Intel Mac / Linux x86_64

cd lab-*/
chmod +x start-lab.sh
./start-lab.sh
```

### Windows

แตก `lab-*-amd64.zip` แล้ว **double-click `start-lab.cmd`**  
หรือเปิด Command Prompt แล้วรัน:

```batch
start-lab.cmd
```

---

## URLs หลังรันสำเร็จ

| Service | URL |
|---------|-----|
| VerifierAPI | http://localhost:5001/swagger |
| IssuerAPI | http://localhost:5002/swagger |
| waltid Wallet | http://localhost:7101 |
| waltid Portal | http://localhost:7102 |
| waltid Issuer API | http://localhost:7002 |
| waltid Verifier API | http://localhost:7003 |

---

## วิธีหยุด

```bash
# macOS / Linux
./stop-lab.sh

# Windows
stop-lab.cmd
```

---

## Troubleshooting

### Windows — "cannot be loaded, not digitally signed"

```
.\start-lab.ps1 cannot be loaded. The file is not digitally signed.
```

**สาเหตุ:** Windows บล็อก `.ps1` ที่ download จาก internet โดย default

**วิธีแก้ (เลือกอย่างใดอย่างหนึ่ง):**

✅ **วิธีที่ 1 — ใช้ `.cmd` แทน (แนะนำ)**
```batch
start-lab.cmd
```
ดับเบิ้ลคลิกได้เลย ไม่ต้องแก้ไขอะไร

✅ **วิธีที่ 2 — Unblock ไฟล์ก่อนรัน**  
เปิด PowerShell แล้วรัน:
```powershell
Unblock-File .\start-lab.ps1
Unblock-File .\stop-lab.ps1
.\start-lab.ps1
```

✅ **วิธีที่ 3 — Bypass ทีละครั้ง**
```powershell
powershell -ExecutionPolicy Bypass -File .\start-lab.ps1
```

✅ **วิธีที่ 4 — แก้ Execution Policy ถาวร** (ต้องใช้สิทธิ์ Admin)
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
.\start-lab.ps1
```

---

### Port ชนกัน — "port is already allocated" หรือ "address already in use"

```
Error: bind: address already in use
```

**สาเหตุ:** port ที่ต้องการถูก process อื่นใช้อยู่

**วิธีตรวจ:**

```bash
# macOS / Linux
lsof -i :5001
lsof -i :5002

# Windows
netstat -ano | findstr :5001
netstat -ano | findstr :5002
```

**วิธีแก้:** หยุด process ที่ใช้ port นั้น แล้วรัน `start-lab.sh` / `start-lab.cmd` ใหม่

---

### Docker ไม่พร้อม — "500 Internal Server Error" หรือ "Cannot connect to the Docker daemon"

```
request returned 500 Internal Server Error for API route and version
http://%2F%2F.%2Fpipe%2FdockerDesktopLinuxEngine/_ping
```
หรือ
```
error during connect: Get http://%2F%2F.%2Fpipe%2Fdocker_engine/...
```

**สาเหตุ:** Docker Desktop ยังไม่ start เสร็จสมบูรณ์ หรือ engine ค้าง

**วิธีแก้ (ทำตามลำดับ):**

1. **รอให้ Docker Desktop พร้อม** — ดูไอคอน Docker ใน System Tray (มุมขวาล่าง)  
   - 🔄 หมุนอยู่ = กำลัง start → รอต่อ  
   - ✅ นิ่ง = พร้อมแล้ว → รัน script ใหม่

2. **Restart Docker Desktop** หากไอคอนค้างหรือมี error  
   คลิกขวาที่ไอคอน Docker → **Restart**  
   รอ 30 วินาที แล้วรัน script ใหม่

3. **เปิด Docker Desktop ถ้ายังไม่ได้เปิด**  
   Start Menu → Docker Desktop → รอจนไอคอนนิ่ง

4. **ตรวจสอบว่า WSL2 ทำงานปกติ** (Windows เท่านั้น)  
   เปิด PowerShell แล้วรัน:
   ```powershell
   wsl --status
   ```
   ถ้า error ให้รัน: `wsl --update` แล้ว restart เครื่อง

---

### Image load ช้า / ค้าง

การ load Docker images ครั้งแรกอาจใช้เวลา 2-5 นาที ขึ้นอยู่กับ machine  
รอจน prompt กลับมาปกติ อย่า Ctrl+C

---

### Wallet แสดง "500 Internal Server Error" ตอน resolvePresentationRequest

```
FetchError: [POST] "/wallet-api/wallet/.../exchange/resolvePresentationRequest": 500
```

**สาเหตุ:** waltid wallet-api อยู่คนละ Docker network กับ verifier-api จึงเรียก `http://verifier-api:8080` ไม่ได้

**วิธีแก้:** ใช้ `start-lab.sh` / `start-lab.cmd` เวอร์ชันล่าสุด — script จะ connect waltid containers เข้า `lab-network` อัตโนมัติแล้ว

หรือ connect ด้วยตนเอง:

```bash
docker compose -f waltid/docker-compose.yaml --profile identity ps -q | \
  xargs -I{} docker network connect lab-network {}
```

แล้ว refresh หน้า wallet ใหม่

---

### "pull access denied for verifier-api" / "repository does not exist"

```
✘ Image verifier-api:latest Error pull access denied for verifier-api
```

**สาเหตุ:** Docker Compose หา image ชื่อ `verifier-api:latest` ไม่เจอในเครื่อง แล้วพยายาม pull จาก Docker Hub  
มักเกิดเมื่อ load image แล้วแต่ tag ไม่ตรง (image อยู่ในเครื่องเป็น `:arm64` / `:amd64`)

**วิธีแก้:** ใช้ `start-lab.sh` / `start-lab.cmd` เวอร์ชันล่าสุด — script จะ retag อัตโนมัติแล้ว  
หรือ retag ด้วยตนเอง:

```bash
# macOS / Linux
docker tag verifier-api:arm64 verifier-api:latest
docker tag issuer-api:arm64 issuer-api:latest
docker tag waltid/wallet-api:arm64 waltid/wallet-api:latest
docker tag waltid/issuer-api:arm64 waltid/issuer-api:latest
docker tag waltid/verifier-api:arm64 waltid/verifier-api:latest
docker tag waltid/verifier-api2:arm64 waltid/verifier-api2:latest
docker tag waltid/portal:arm64 waltid/portal:latest
docker tag waltid/waltid-demo-wallet:arm64 waltid/waltid-demo-wallet:latest
docker tag waltid/waltid-dev-wallet:arm64 waltid/waltid-dev-wallet:latest
# สำหรับ Intel Mac / Linux ให้เปลี่ยน :arm64 → :amd64
```

แล้วรัน `./start-lab.sh` อีกครั้ง

---

### Services start แล้วแต่เข้าไม่ได้ (Connection refused)

**วิธีตรวจ:**
```bash
docker ps
```
ต้องเห็น containers ทั้งหมดอยู่ใน state `Up`

ถ้า container มี state `Exiting` หรือ `Restarting`:
```bash
docker logs verifier-api
docker logs issuer-api
```
แล้วแปะ log มาให้ทีมช่วยดู
