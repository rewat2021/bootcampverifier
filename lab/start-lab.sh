#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Detect architecture
ARCH=$(uname -m)
case $ARCH in
  x86_64)        TAG="amd64" ;;
  aarch64|arm64) TAG="arm64" ;;
  *)
    echo "ERROR: Unsupported architecture: $ARCH"
    exit 1
    ;;
esac

echo "=== Lab Setup ==="
echo "Architecture: $ARCH ($TAG)"
echo ""

# ── ตรวจว่า Docker พร้อมใช้งาน ──────────────────────────────────────────
echo "[0/4] Checking Docker..."
MAX_WAIT=60
WAITED=0
until docker info >/dev/null 2>&1; do
  if [ "$WAITED" -ge "$MAX_WAIT" ]; then
    echo ""
    echo "ERROR: Docker is not responding after ${MAX_WAIT}s."
    echo ""
    echo "วิธีแก้:"
    echo "  1. เปิด Docker Desktop และรอจนไอคอนนิ่ง"
    echo "  2. ถ้าเปิดอยู่แล้ว ให้ Restart Docker Desktop"
    echo "  3. แล้วรัน ./start-lab.sh อีกครั้ง"
    exit 1
  fi
  echo "  Docker not ready yet, waiting... (${WAITED}s)"
  sleep 5
  WAITED=$((WAITED + 5))
done
echo "  Docker is ready."
echo ""

# Create shared Docker network
echo "[1/4] Creating shared network 'lab-network'..."
docker network create lab-network 2>/dev/null && echo "  Created." || echo "  Already exists, skipping."

# Load images
echo ""
echo "[2/4] Loading Docker images..."
IMAGES_DIR="$SCRIPT_DIR/images"

ALL_IMAGES=(
  "verifier-api"
  "issuer-api"
  "waltid-wallet-api"
  "waltid-issuer-api"
  "waltid-verifier-api"
  "waltid-verifier-api2"
  "waltid-portal"
  "waltid-demo-wallet"
  "waltid-dev-wallet"
)

for IMAGE in "${ALL_IMAGES[@]}"; do
  FILE="$IMAGES_DIR/${IMAGE}-linux-${TAG}.tar.gz"
  if [ -f "$FILE" ]; then
    echo "  Loading $IMAGE..."
    # load คืนค่า "Loaded image: <name>:<arch>" — เอาไป retag เป็น :latest
    LOADED=$(docker load < "$FILE" | grep "Loaded image:" | awk '{print $NF}')
    echo "    Loaded: $LOADED"
    BASE="${LOADED%:*}"   # ตัด :arm64 / :amd64 ออก
    if [ "${LOADED}" != "${BASE}:latest" ]; then
      docker tag "$LOADED" "${BASE}:latest"
      echo "    Tagged: ${BASE}:latest"
    fi
  else
    echo "  ERROR: $FILE not found."
    echo "         Download from GitHub Releases and place in the images/ folder."
    exit 1
  fi
done

# Start services
echo ""
echo "[3/4] Starting services..."

echo "  Starting VerifierAPI + MySQL..."
docker compose -f "$SCRIPT_DIR/verifier/docker-compose.yml" up -d

echo "  Starting IssuerAPI + MySQL..."
docker compose -f "$SCRIPT_DIR/issuer/docker-compose.yml" up -d

echo "  Starting waltid services (อาจใช้เวลา 1-5 นาทีถ้าต้อง pull caddy/postgres จาก internet)..."
docker compose -f "$SCRIPT_DIR/waltid/docker-compose.yaml" --profile identity up -d

# ── เชื่อม waltid containers เข้า lab-network ────────────────────────────
# waltid docker-compose อยู่บน network ของตัวเอง ต้อง connect เข้า lab-network
# เพื่อให้ wallet-api เรียก verifier-api:8080 และ issuer-api:8080 ได้
echo "  Connecting waltid services to lab-network..."
docker compose -f "$SCRIPT_DIR/waltid/docker-compose.yaml" --profile identity ps -q 2>/dev/null \
  | while read -r CID; do
      docker network connect lab-network "$CID" 2>/dev/null && echo "    ✓ Connected container $CID" || true
    done

echo ""
echo "[4/4] All services started."
echo ""
echo "  VerifierAPI    : http://localhost:5001/swagger"
echo "  IssuerAPI      : http://localhost:5002/swagger"
echo "  waltid wallet  : http://localhost:7101"
echo "  waltid portal  : http://localhost:7102"
echo "  waltid issuer  : http://localhost:7002"
echo "  waltid verifier: http://localhost:7003"
echo ""
echo "To stop all services, run: ./stop-lab.sh"
