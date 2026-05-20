#!/usr/bin/env bash
# Update all tool databases and templates across clawscan containers.
set -euo pipefail

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  clawscan — update"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

CONTAINERS=(clawscan-osint clawscan-portscan clawscan-vulnscan clawscan-webscan clawscan-cmsscan)
for c in "${CONTAINERS[@]}"; do
  if ! docker ps --format '{{.Names}}' | grep -q "^${c}$"; then
    echo "[!] Container not running: $c"
    echo "    Run: docker compose up -d"
    exit 1
  fi
done

# ── nuclei templates ─────────────────────────────────────────────
echo ""
echo "[1/4] Updating nuclei templates..."
docker exec clawscan-vulnscan \
  nuclei -update-templates -update-template-dir /root/nuclei-templates
echo "      Done."

# ── WPScan vulnerability database ────────────────────────────────
echo ""
echo "[2/4] Updating WPScan database..."
docker exec clawscan-cmsscan wpscan --update
echo "      Done."

# ── SecLists (webscan) ───────────────────────────────────────────
echo ""
echo "[3/4] Updating SecLists..."
docker exec clawscan-webscan \
  bash -c "cd /opt/seclists && git pull --ff-only"
echo "      Done."

# ── testssl.sh ───────────────────────────────────────────────────
echo ""
echo "[4/4] Updating testssl.sh..."
docker exec clawscan-vulnscan \
  bash -c "cd /opt/testssl && git pull --ff-only"
echo "      Done."

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  All updates complete."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
