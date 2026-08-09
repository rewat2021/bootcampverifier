#!/bin/bash
# import-lab-data.sh — Import MySQL data into running lab containers
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
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

echo "=== Import Lab Data ==="
echo ""

if [ -z "$1" ]; then
    echo "Usage: ./import-lab-data.sh <lab-data-YYYYMMDD_HHMMSS.zip>"
    echo ""
    echo "Available export files:"
    ls "$SCRIPT_DIR"/lab-data-*.zip 2>/dev/null || echo "  (none found)"
    exit 1
fi

ZIP_FILE="$1"
if [ ! -f "$ZIP_FILE" ]; then
    ZIP_FILE="$SCRIPT_DIR/$1"
fi
if [ ! -f "$ZIP_FILE" ]; then
    echo "ERROR: File not found: $1"
    exit 1
fi

IMPORT_DIR="$SCRIPT_DIR/lab-data-import-tmp"
rm -rf "$IMPORT_DIR" && mkdir -p "$IMPORT_DIR"

echo "Extracting $ZIP_FILE..."
unzip -q "$ZIP_FILE" -d "$IMPORT_DIR"

# Find SQL files
VERIFIER_SQL=$(find "$IMPORT_DIR" -name "verifier.sql" | head -1)
ISSUER_SQL=$(find "$IMPORT_DIR" -name "issuer.sql" | head -1)

# Import Verifier DB
if [ -n "$VERIFIER_SQL" ]; then
    echo ""
    echo "[1/2] Importing Verifier database..."
    if docker exec verifier-mysql mysqladmin ping -uroot -p"$DB_PASS" --silent 2>/dev/null; then
        docker exec -i verifier-mysql mysql -uroot -p"$DB_PASS" verifier \
            2>/dev/null < "$VERIFIER_SQL"
        echo "  Done"
    else
        echo "  ERROR: verifier-mysql is not running. Start the lab first."
        rm -rf "$IMPORT_DIR"
        exit 1
    fi
else
    echo "[1/2] verifier.sql not found in zip, skipping"
fi

# Import Issuer DB
if [ -n "$ISSUER_SQL" ]; then
    echo "[2/2] Importing Issuer database..."
    if docker exec issuer-mysql mysqladmin ping -uroot -p"$DB_PASS" --silent 2>/dev/null; then
        docker exec -i issuer-mysql mysql -uroot -p"$DB_PASS" issuer \
            2>/dev/null < "$ISSUER_SQL"
        echo "  Done"
    else
        echo "  WARNING: issuer-mysql is not running, skipping"
    fi
else
    echo "[2/2] issuer.sql not found in zip, skipping"
fi

rm -rf "$IMPORT_DIR"

echo ""
echo "Import complete!"
echo ""
echo "Verify:"
echo "  docker exec -it verifier-mysql mysql -uroot -p${DB_PASS} verifier -e \"SELECT COUNT(*) FROM dbverifiersession; SELECT COUNT(*) FROM dbverifierresponse;\""
