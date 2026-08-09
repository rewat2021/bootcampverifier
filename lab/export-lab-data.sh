#!/bin/bash
# export-lab-data.sh — Export MySQL data from running lab containers
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
EXPORT_DIR="$SCRIPT_DIR/lab-data-export"
# SECURITY (Phase 0 remediation, 2026-08-08): no hardcoded fallback password.
# Read from verifier/.env (generated per-release by CI) or the environment.
DB_PASS="${MYSQL_ROOT_PASSWORD:-}"
if [ -z "$DB_PASS" ] && [ -f "$SCRIPT_DIR/verifier/.env" ]; then
  DB_PASS="$(grep -m1 '^MYSQL_ROOT_PASSWORD=' "$SCRIPT_DIR/verifier/.env" | cut -d= -f2-)"
fi
if [ -z "$DB_PASS" ]; then
  echo "ERROR: MYSQL_ROOT_PASSWORD not set and not found in verifier/.env" >&2
  exit 1
fi
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
OUT_FILE="$SCRIPT_DIR/lab-data-${TIMESTAMP}.zip"

echo "=== Export Lab Data ==="
echo ""

mkdir -p "$EXPORT_DIR"

# Export Verifier DB
echo "[1/2] Exporting Verifier database..."
if docker exec verifier-mysql mysqladmin ping -uroot -p"$DB_PASS" --silent 2>/dev/null; then
    docker exec verifier-mysql mysqldump -uroot -p"$DB_PASS" verifier \
        2>/dev/null > "$EXPORT_DIR/verifier.sql"
    ROWS=$(grep -c "^INSERT INTO" "$EXPORT_DIR/verifier.sql" 2>/dev/null || echo "0")
    echo "  Done — ${ROWS} INSERT statements"
else
    echo "  ERROR: verifier-mysql is not running"
    exit 1
fi

# Export Issuer DB
echo "[2/2] Exporting Issuer database..."
if docker exec issuer-mysql mysqladmin ping -uroot -p"$DB_PASS" --silent 2>/dev/null; then
    docker exec issuer-mysql mysqldump -uroot -p"$DB_PASS" issuer \
        2>/dev/null > "$EXPORT_DIR/issuer.sql"
    ROWS=$(grep -c "^INSERT INTO" "$EXPORT_DIR/issuer.sql" 2>/dev/null || echo "0")
    echo "  Done — ${ROWS} INSERT statements"
else
    echo "  WARNING: issuer-mysql is not running, skipping"
fi

# Package to zip
echo ""
echo "Packaging..."
cd "$SCRIPT_DIR"
zip -r "$OUT_FILE" "lab-data-export/" -x "*.DS_Store" >/dev/null
rm -rf "$EXPORT_DIR"

echo ""
echo "Export complete!"
echo "  File: $OUT_FILE"
echo ""
echo "Copy this file to machine B, then run:"
echo "  ./import-lab-data.sh lab-data-${TIMESTAMP}.zip"
