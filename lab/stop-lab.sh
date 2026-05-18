#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "=== Stopping Lab Services ==="

docker compose -f "$SCRIPT_DIR/verifier/docker-compose.yml" down -v
docker compose -f "$SCRIPT_DIR/issuer/docker-compose.yml" down -v 
docker compose -f "$SCRIPT_DIR/waltid/docker-compose.yaml" --profile identity down -v

echo "All services stopped."
